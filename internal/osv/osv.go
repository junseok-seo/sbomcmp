// Package osv talks to an OSV-compatible vulnerability API (api.osv.dev by
// default): batch purl queries followed by bounded detail fetches that supply
// severity, aliases, summary and the fixed version.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

// DefaultEndpoint is the public OSV API.
const DefaultEndpoint = "https://api.osv.dev"

// Client queries one OSV-compatible server.
type Client struct {
	Endpoint   string
	APIKey     string // optional bearer token
	HTTP       *http.Client
	MaxDetails int // cap on per-vuln detail fetches
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
		HTTP: &http.Client{Timeout: timeout}, MaxDetails: 80}
}

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
	Affected []struct {
		Package struct {
			Purl string `json:"purl"`
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Severity string `json:"severity"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
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
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(data)), 200))
	}
	return data, nil
}

// Enrich fills rows[idx] with vulnerabilities. Detail fetches are capped at
// MaxDetails and prioritize rows the tools disagree on, because those drive
// the recommendation; the rest keep IDs only with UNKNOWN severity.
func (c *Client) Enrich(ctx context.Context, rows []model.Row, idx []int, purlFor func(model.Row) string, source string) error {
	purls := make([]string, len(idx))
	for k, i := range idx {
		purls[k] = purlFor(rows[i])
	}
	ids, err := c.QueryBatch(ctx, purls)
	if err != nil {
		return err
	}
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
	if c.MaxDetails > 0 && len(refs) > c.MaxDetails {
		refs = refs[:c.MaxDetails]
	}
	// One detail per distinct ID; the same advisory often hits several rows.
	details := map[string]*Vuln{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, rf := range refs {
		id := rows[rf.row].Vulns[rf.vi].ID
		mu.Lock()
		_, seen := details[id]
		if !seen {
			details[id] = nil
		}
		mu.Unlock()
		if seen {
			continue
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d, err := c.Detail(ctx, id)
			if err != nil {
				return
			}
			mu.Lock()
			details[id] = d
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	for _, rf := range refs {
		v := &rows[rf.row].Vulns[rf.vi]
		d := details[v.ID]
		if d == nil {
			continue
		}
		v.Aliases = d.Aliases
		v.Summary = truncate(d.Summary, 160)
		v.Severity, v.Score = SeverityOf(d)
		v.Fixed = FixedFor(d)
	}
	for _, i := range idx {
		rows[i].MaxSev = model.MaxSeverity(rows[i].Vulns)
	}
	return nil
}

// SeverityOf buckets an OSV record: CVSS v3 vector first, then the database
// or ecosystem-specific label, else UNKNOWN.
func SeverityOf(v *Vuln) (string, float64) {
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

// FixedFor returns the first "fixed" event found in the record.
func FixedFor(v *Vuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f, ok := e["fixed"]; ok && f != "" {
					return f
				}
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
