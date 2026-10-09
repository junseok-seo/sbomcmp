// Package osv talks to an OSV-compatible vulnerability API (api.osv.dev by
// default): batch purl queries followed by bounded detail fetches that supply
// severity, aliases, summary and the fixed version.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/model"
	"github.com/junseok-seo/sbomcmp/internal/purl"
)

// DefaultEndpoint is the public OSV API.
const DefaultEndpoint = "https://api.osv.dev"

// DefaultMaxDetails is the default cap on distinct advisories whose details
// are fetched per scan. api.osv.dev answers /v1/vulns/{id} in about 100 ms, so
// 600 fetches at DefaultConcurrency take a few seconds.
const DefaultMaxDetails = 600

// DefaultConcurrency is the number of detail fetches in flight at once.
const DefaultConcurrency = 16

// Client queries one OSV-compatible server.
type Client struct {
	Endpoint    string
	APIKey      string // optional bearer token
	HTTP        *http.Client
	MaxDetails  int // cap on distinct advisories fetched (0 = unlimited)
	Concurrency int // parallel detail fetches (0 = DefaultConcurrency)

	// backoff holds the pauses before each retry of a detail fetch that was
	// rate limited (HTTP 429) or failed in transport. Tests shorten it.
	backoff []time.Duration
}

// New returns a client with sane defaults.
func New(endpoint, apiKey string, timeout time.Duration) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{Endpoint: strings.TrimRight(endpoint, "/"), APIKey: apiKey,
		HTTP: &http.Client{Timeout: timeout}, MaxDetails: DefaultMaxDetails, Concurrency: DefaultConcurrency,
		backoff: defaultBackoff}
}

var defaultBackoff = []time.Duration{time.Second, 2 * time.Second}

type batchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Vuln is the subset of an OSV record sbomcmp reads.
type Vuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []Affected `json:"affected"`
	// VDBSeverity is VDB's own rating (CVSS v3/v4 computed server-side) when
	// a VDB deployment serves the OSV endpoints. Preferred when present.
	VDBSeverity *struct {
		Bucket string  `json:"bucket"`
		Score  float64 `json:"score"`
		Source string  `json:"source"`
	} `json:"vdb_severity"`
}

// Affected is one package entry of an OSV record. The affected set is the
// union of Ranges and the explicit Versions list; MAL-* reports use only the
// list.
type Affected struct {
	Package struct {
		Purl      string `json:"purl"`
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"` // SEMVER / ECOSYSTEM / GIT
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	Versions          []string `json:"versions"`
	EcosystemSpecific struct {
		Severity string `json:"severity"`
	} `json:"ecosystem_specific"`
}

// QueryBatch returns, for each purl, the IDs of matching vulnerabilities.
func (c *Client) QueryBatch(ctx context.Context, purls []string) ([][]string, error) {
	out := make([][]string, len(purls))
	const chunk = 500
	for start := 0; start < len(purls); start += chunk {
		end := min(start+chunk, len(purls))
		type q struct {
			Package struct {
				Purl string `json:"purl"`
			} `json:"package"`
		}
		qs := make([]q, 0, end-start)
		for _, p := range purls[start:end] {
			var one q
			one.Package.Purl = p
			qs = append(qs, one)
		}
		body, _ := json.Marshal(map[string]any{"queries": qs})
		data, err := c.do(ctx, "POST", c.Endpoint+"/v1/querybatch", body)
		if err != nil {
			return nil, fmt.Errorf("querybatch: %w", err)
		}
		var br batchResp
		if err := json.Unmarshal(data, &br); err != nil {
			return nil, fmt.Errorf("querybatch decode: %w", err)
		}
		for k, r := range br.Results {
			if start+k >= len(out) {
				break
			}
			for _, v := range r.Vulns {
				out[start+k] = append(out[start+k], v.ID)
			}
		}
	}
	return out, nil
}

// Detail fetches one record.
func (c *Client) Detail(ctx context.Context, id string) (*Vuln, error) {
	data, err := c.do(ctx, "GET", c.Endpoint+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	var v Vuln
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *Client) do(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sbomcmp")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return nil, &httpError{code: resp.StatusCode, body: truncate(strings.TrimSpace(string(data)), 200)}
	}
	return data, nil
}

// httpError is a non-2xx answer. Transport failures are returned as-is.
type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.code, e.body) }

// retryable reports whether a detail fetch error is worth another attempt:
// rate limiting and transport failures are; a 404 or a decode error is not.
func retryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.code == http.StatusTooManyRequests
	}
	var je *json.SyntaxError
	if errors.As(err, &je) {
		return false
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// detailWithRetry fetches one record, pausing c.backoff[0], c.backoff[1], …
// between attempts that were rate limited or failed in transport, and gives
// up on the ID once the pauses run out.
func (c *Client) detailWithRetry(ctx context.Context, id string) (*Vuln, error) {
	waits := c.backoff
	if waits == nil {
		waits = defaultBackoff
	}
	for attempt := 0; ; attempt++ {
		d, err := c.Detail(ctx, id)
		if err == nil {
			return d, nil
		}
		if attempt >= len(waits) || !retryable(err) || ctx.Err() != nil {
			return nil, err
		}
		select {
		case <-time.After(waits[attempt]):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Stats describes what one Enrich call managed to do.
type Stats struct {
	Answered int // rows the batch query answered (all of them, or none on error)
	// Advisories counts distinct advisory IDs the batch query returned;
	// Scored is how many of them got a detail record.
	Advisories int
	Scored     int
	// DetailsCapped counts distinct advisories left at UNKNOWN: those past
	// MaxDetails plus those whose fetch failed (DetailsFailed is the latter).
	DetailsCapped int
	DetailsFailed int
}

// Enrich fills rows[idx] with vulnerabilities. Detail fetches cover at most
// MaxDetails distinct advisories and take rows the tools disagree on first,
// because those drive the recommendation; advisories past the cap, and those
// whose fetch failed even after retries, keep their ID with UNKNOWN severity
// and are counted in Stats.DetailsCapped.
func (c *Client) Enrich(ctx context.Context, rows []model.Row, idx []int, purlFor func(model.Row) string, source string) (Stats, error) {
	var st Stats
	purls := make([]string, len(idx))
	for k, i := range idx {
		purls[k] = purlFor(rows[i])
	}
	ids, err := c.QueryBatch(ctx, purls)
	if err != nil {
		return st, err
	}
	st.Answered = len(idx)
	type ref struct{ row, vi int }
	var refs []ref
	for k, i := range idx {
		for _, id := range ids[k] {
			rows[i].Vulns = append(rows[i].Vulns, model.Vuln{ID: id, Severity: "UNKNOWN", Source: source})
			refs = append(refs, ref{i, len(rows[i].Vulns) - 1})
		}
	}
	sort.SliceStable(refs, func(a, b int) bool {
		ra, rb := rows[refs[a].row].Agreement == "all", rows[refs[b].row].Agreement == "all"
		return !ra && rb
	})
	// One detail per distinct ID, in disagreement-first order; the same
	// advisory often hits several rows and must count once against the cap.
	var order []string
	details := map[string]*Vuln{}
	for _, rf := range refs {
		id := rows[rf.row].Vulns[rf.vi].ID
		if _, seen := details[id]; seen {
			continue
		}
		details[id] = nil
		order = append(order, id)
	}
	st.Advisories = len(order)
	fetch := order
	if c.MaxDetails > 0 && len(fetch) > c.MaxDetails {
		fetch = fetch[:c.MaxDetails]
	}
	conc := c.Concurrency
	if conc <= 0 {
		conc = DefaultConcurrency
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	for _, id := range fetch {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d, err := c.detailWithRetry(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				st.DetailsFailed++
				return
			}
			details[id] = d
		}(id)
	}
	wg.Wait()
	st.Scored = len(fetch) - st.DetailsFailed
	st.DetailsCapped = st.Advisories - st.Scored
	for _, rf := range refs {
		v := &rows[rf.row].Vulns[rf.vi]
		d := details[v.ID]
		if d == nil {
			continue
		}
		v.Aliases = d.Aliases
		v.Summary = truncate(d.Summary, 160)
		v.Severity, v.Score = SeverityOf(d)
		v.Fixed = FixedFor(d, purlFor(rows[rf.row]), rows[rf.row].Version)
	}
	for _, i := range idx {
		rows[i].MaxSev = model.MaxSeverity(rows[i].Vulns)
	}
	return st, nil
}

// SeverityOf buckets an OSV record: CVSS v3 vector first, then the database
// or ecosystem-specific label, else UNKNOWN.
func SeverityOf(v *Vuln) (string, float64) {
	if vs := v.VDBSeverity; vs != nil && vs.Bucket != "" && vs.Bucket != "none" {
		b := strings.ToUpper(vs.Bucket)
		if b == "MODERATE" {
			b = "MEDIUM"
		}
		return b, vs.Score
	}
	for _, s := range v.Severity {
		if sc := BaseScore(s.Score); sc > 0 {
			return Bucket(sc), sc
		}
	}
	if s := strings.ToUpper(v.DatabaseSpecific.Severity); s != "" {
		if s == "MODERATE" {
			s = "MEDIUM"
		}
		return s, 0
	}
	for _, a := range v.Affected {
		if s := strings.ToUpper(a.EcosystemSpecific.Severity); s != "" {
			return s, 0
		}
	}
	return "UNKNOWN", 0
}

// FixedFor returns the version that fixes the record for the given package:
// only affected entries for that purl are considered, GIT ranges (commit
// hashes) are skipped, and among several fixed events the smallest one above
// the current version wins. An empty string means no fixed version is known.
func FixedFor(v *Vuln, queryPurl, current string) string {
	want := purl.NameKey(purl.Normalize(purl.Parse(queryPurl)))
	var candidates []string
	for _, a := range v.Affected {
		if !affectedMatches(a, want) {
			continue
		}
		for _, r := range a.Ranges {
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			for _, e := range r.Events {
				if f, ok := e["fixed"]; ok && f != "" {
					candidates = append(candidates, f)
				}
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	cur := strings.TrimPrefix(current, "v")
	best := ""
	for _, c := range candidates {
		cc := strings.TrimPrefix(c, "v")
		if cur != "" && compareVersions(cc, cur) <= 0 {
			continue // already at or past this fix
		}
		if best == "" || compareVersions(cc, best) < 0 {
			best = cc
		}
	}
	if best == "" {
		// Every fix is at or below the current version: report the highest so
		// the user sees the record is not about a future version.
		for _, c := range candidates {
			cc := strings.TrimPrefix(c, "v")
			if best == "" || compareVersions(cc, best) > 0 {
				best = cc
			}
		}
	}
	return best
}

// affectedMatches reports whether an affected entry is about the package
// identified by the normalized name key (type/namespace/name).
func affectedMatches(a Affected, want string) bool {
	if a.Package.Purl != "" {
		if purl.NameKey(purl.Normalize(purl.Parse(a.Package.Purl))) == want {
			return true
		}
	}
	if a.Package.Name != "" && a.Package.Ecosystem != "" {
		eco := strings.ToLower(a.Package.Ecosystem)
		if i := strings.Index(eco, ":"); i > 0 { // "Debian:12" → "debian"
			eco = eco[:i]
		}
		p := purl.Normalize(purl.PURL{Type: eco, Name: a.Package.Name, Qualifiers: map[string]string{}})
		if purl.NameKey(p) == want {
			return true
		}
	}
	return false
}

// compareVersions orders dotted versions numerically segment by segment,
// treating a pre-release suffix as lower than the plain version. It is
// deliberately simple; ties and unparsable segments compare as strings.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	pa, sa := splitPre(a)
	pb, sb := splitPre(b)
	as, bs := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xi, xe := strconv.Atoi(x)
		yi, ye := strconv.Atoi(y)
		switch {
		case xe == nil && ye == nil:
			if xi != yi {
				if xi < yi {
					return -1
				}
				return 1
			}
		default:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case sa == "" && sb != "":
		return 1
	case sa != "" && sb == "":
		return -1
	}
	return strings.Compare(sa, sb)
}

func splitPre(v string) (string, string) {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
