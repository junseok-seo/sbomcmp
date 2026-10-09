package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

func TestEnrichAgainstFakeServer(t *testing.T) {
	var gotPurls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Purl string } `json:"package"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			res := []any{}
			for _, q := range req.Queries {
				gotPurls = append(gotPurls, q.Package.Purl)
				if strings.Contains(q.Package.Purl, "qs@") {
					res = append(res, map[string]any{"vulns": []map[string]string{{"id": "GHSA-1"}}})
				} else {
					res = append(res, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			json.NewEncoder(w).Encode(map[string]any{
				"id": "GHSA-1", "aliases": []string{"CVE-1"}, "summary": "proto pollution",
				"severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
				"affected": []any{map[string]any{"package": map[string]string{"purl": "pkg:npm/qs"}, "ranges": []any{map[string]any{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "6.11.1"}}}}}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rows := []model.Row{
		{Key: "npm/qs@6.11.0", Type: "npm", Name: "qs", Version: "6.11.0", Agreement: "single"},
		{Key: "npm/lodash@4.17.21", Type: "npm", Name: "lodash", Version: "4.17.21", Agreement: "all"},
	}
	c := New(srv.URL, "", 0)
	st, err := c.Enrich(context.Background(), rows, []int{0, 1}, func(r model.Row) string { return "pkg:" + r.Type + "/" + r.Name + "@" + r.Version }, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if st.Answered != 2 || st.DetailsCapped != 0 {
		t.Fatalf("stats: %+v", st)
	}
	if len(gotPurls) != 2 {
		t.Fatalf("expected 2 queries, got %v", gotPurls)
	}
	v := rows[0].Vulns
	if len(v) != 1 || v[0].ID != "GHSA-1" || v[0].Severity != "HIGH" || v[0].Score != 7.5 || v[0].Fixed != "6.11.1" || v[0].Aliases[0] != "CVE-1" {
		t.Fatalf("bad enrichment: %+v", v)
	}
	if rows[0].MaxSev != "HIGH" || len(rows[1].Vulns) != 0 {
		t.Fatalf("bad rows: %+v", rows)
	}
}

// With MaxDetails=1 only one advisory is fetched; the rest stay UNKNOWN and
// are counted in DetailsCapped. Rows the tools disagree on are fetched first,
// and a fetched advisory is applied to every row it hits, even past the cap.
func TestEnrichReportsDetailCap(t *testing.T) {
	var detailCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Purl string } `json:"package"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			res := []any{}
			for _, q := range req.Queries {
				switch {
				case strings.Contains(q.Package.Purl, "qs@"):
					res = append(res, map[string]any{"vulns": []map[string]string{{"id": "GHSA-1"}, {"id": "GHSA-2"}}})
				case strings.Contains(q.Package.Purl, "lodash@"):
					res = append(res, map[string]any{"vulns": []map[string]string{{"id": "GHSA-1"}}})
				default:
					res = append(res, map[string]any{"vulns": []map[string]string{{"id": "GHSA-3"}}})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			detailCalls++
			json.NewEncoder(w).Encode(map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/vulns/"),
				"database_specific": map[string]string{"severity": "HIGH"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rows := []model.Row{
		{Key: "npm/lodash@4.17.21", Type: "npm", Name: "lodash", Version: "4.17.21", Agreement: "all"},
		{Key: "npm/qs@6.11.0", Type: "npm", Name: "qs", Version: "6.11.0", Agreement: "single"},
		{Key: "npm/ms@2.1.3", Type: "npm", Name: "ms", Version: "2.1.3", Agreement: "all"},
	}
	c := New(srv.URL, "", 0)
	c.MaxDetails = 1
	st, err := c.Enrich(context.Background(), rows, []int{0, 1, 2}, func(r model.Row) string { return "pkg:" + r.Type + "/" + r.Name + "@" + r.Version }, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if detailCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", detailCalls)
	}
	// 4 advisory references, 1 fetched (GHSA-1 on the disagreeing qs row),
	// GHSA-1 on lodash reuses it; GHSA-2 and GHSA-3 are capped.
	if st.Answered != 3 || st.DetailsCapped != 2 {
		t.Fatalf("stats: %+v", st)
	}
	if rows[1].Vulns[0].Severity != "HIGH" || rows[1].Vulns[1].Severity != "UNKNOWN" || rows[1].MaxSev != "HIGH" {
		t.Fatalf("qs: %+v", rows[1].Vulns)
	}
	if rows[0].Vulns[0].Severity != "HIGH" {
		t.Fatalf("lodash should reuse the fetched detail: %+v", rows[0].Vulns)
	}
	if rows[2].Vulns[0].Severity != "UNKNOWN" || rows[2].MaxSev != "UNKNOWN" {
		t.Fatalf("ms: %+v", rows[2].Vulns)
	}
}

func TestFixedForMatchesPackageAndSkipsGit(t *testing.T) {
	var v Vuln
	json.Unmarshal([]byte(`{"id":"X","affected":[
	  {"package":{"ecosystem":"npm","name":"other"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]},
	  {"package":{"purl":"pkg:npm/qs"},"ranges":[
	     {"type":"GIT","events":[{"introduced":"0"},{"fixed":"deadbeefcafe"}]},
	     {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"6.2.4"},{"introduced":"6.3.0"},{"fixed":"6.11.1"},{"introduced":"6.12.0"},{"fixed":"6.14.0"}]}]}
	]}`), &v)
	if got := FixedFor(&v, "pkg:npm/qs@6.11.0", "6.11.0"); got != "6.11.1" {
		t.Fatalf("want smallest fix above current, got %q", got)
	}
	if got := FixedFor(&v, "pkg:npm/qs@6.2.0", "6.2.0"); got != "6.2.4" {
		t.Fatalf("want 6.2.4, got %q", got)
	}
	if got := FixedFor(&v, "pkg:npm/nothing@1.0.0", "1.0.0"); got != "" {
		t.Fatalf("unrelated package must not borrow a fix, got %q", got)
	}
	var g Vuln
	json.Unmarshal([]byte(`{"id":"G","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.17.0"}]}]}]}`), &g)
	if got := FixedFor(&g, "pkg:golang/golang.org/x/net@v0.10.0", "0.10.0"); got != "0.17.0" {
		t.Fatalf("ecosystem label Go must map to golang purls, got %q", got)
	}
}

func TestSeverityPrefersVDBRatingAndReadsVersionsList(t *testing.T) {
	var v Vuln
	json.Unmarshal([]byte(`{"id":"MAL-1","vdb_severity":{"bucket":"critical","score":0,"source":"malicious"},
	  "affected":[{"package":{"purl":"pkg:npm/chalk"},"versions":["5.6.1"]}]}`), &v)
	if b, _ := SeverityOf(&v); b != "CRITICAL" {
		t.Fatalf("vdb_severity should win, got %s", b)
	}
	if len(v.Affected) != 1 || len(v.Affected[0].Versions) != 1 || v.Affected[0].Versions[0] != "5.6.1" {
		t.Fatalf("versions list not read: %+v", v.Affected)
	}
	var w Vuln
	json.Unmarshal([]byte(`{"id":"V4","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}`), &w)
	if b, sc := SeverityOf(&w); b != "CRITICAL" || sc != 9.3 {
		t.Fatalf("cvss 4.0 vector: %s %.1f", b, sc)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := [][3]string{{"6.11.1", "6.11.0", "1"}, {"6.2.4", "6.11.1", "-1"}, {"1.0.0-rc1", "1.0.0", "-1"}, {"2.0", "2.0.0", "-1"}, {"1.10", "1.9", "1"}}
	for _, c := range cases {
		got := compareVersions(c[0], c[1])
		want := map[string]int{"1": 1, "-1": -1, "0": 0}[c[2]]
		if (got > 0) != (want > 0) || (got < 0) != (want < 0) {
			t.Errorf("%s vs %s: got %d want %s", c[0], c[1], got, c[2])
		}
	}
}

// fakeOSV serves a querybatch that answers each purl with the IDs idsFor
// returns, and detail records from detail (which may fail a request by
// writing a status and returning false).
func fakeOSV(t *testing.T, idsFor func(purl string) []string, detail func(w http.ResponseWriter, id string) bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Purl string } `json:"package"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			res := []any{}
			for _, q := range req.Queries {
				var vulns []map[string]string
				for _, id := range idsFor(q.Package.Purl) {
					vulns = append(vulns, map[string]string{"id": id})
				}
				res = append(res, map[string]any{"vulns": vulns})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			if !detail(w, id) {
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"id": id, "database_specific": map[string]string{"severity": "HIGH"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func purlOf(r model.Row) string { return "pkg:" + r.Type + "/" + r.Name + "@" + r.Version }

// 150 rows with two advisories each (300 distinct IDs) all get scored under
// the default cap, with one detail fetch per ID.
func TestEnrichScoresHundredsOfAdvisoriesByDefault(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	srv := fakeOSV(t, func(purl string) []string {
		n := strings.TrimPrefix(strings.SplitN(purl, "@", 2)[0], "pkg:npm/p")
		return []string{"GHSA-" + n + "-a", "GHSA-" + n + "-b"}
	}, func(w http.ResponseWriter, id string) bool {
		mu.Lock()
		calls[id]++
		mu.Unlock()
		return true
	})
	var rows []model.Row
	var idx []int
	for i := 0; i < 150; i++ {
		agreement := "all"
		if i%3 == 0 {
			agreement = "single"
		}
		rows = append(rows, model.Row{Type: "npm", Name: fmt.Sprintf("p%d", i), Version: "1.0.0", Agreement: agreement})
		idx = append(idx, i)
	}
	c := New(srv.URL, "", 0)
	if c.MaxDetails != DefaultMaxDetails || c.Concurrency != DefaultConcurrency {
		t.Fatalf("defaults: %+v", c)
	}
	st, err := c.Enrich(context.Background(), rows, idx, purlOf, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if st.Answered != 150 || st.Advisories != 300 || st.Scored != 300 || st.DetailsCapped != 0 || st.DetailsFailed != 0 {
		t.Fatalf("stats: %+v", st)
	}
	if len(calls) != 300 {
		t.Fatalf("expected 300 distinct detail fetches, got %d", len(calls))
	}
	for id, n := range calls {
		if n != 1 {
			t.Fatalf("%s fetched %d times", id, n)
		}
	}
	for _, r := range rows {
		if len(r.Vulns) != 2 || r.Vulns[0].Severity != "HIGH" || r.Vulns[1].Severity != "HIGH" || r.MaxSev != "HIGH" {
			t.Fatalf("row %s not scored: %+v", r.Name, r.Vulns)
		}
	}
}

// A 429 is retried after the backoff pauses; the third attempt succeeds and
// the advisory is scored. A fetch that keeps failing is given up on after the
// pauses run out and counted in DetailsCapped/DetailsFailed, and a 404 is not
// retried at all.
func TestEnrichRetriesRateLimit(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	srv := fakeOSV(t, func(purl string) []string {
		switch {
		case strings.Contains(purl, "/qs@"):
			return []string{"GHSA-flaky"}
		case strings.Contains(purl, "/ms@"):
			return []string{"GHSA-dead"}
		case strings.Contains(purl, "/gone@"):
			return []string{"GHSA-gone"}
		}
		return []string{"GHSA-ok"}
	}, func(w http.ResponseWriter, id string) bool {
		mu.Lock()
		calls[id]++
		n := calls[id]
		mu.Unlock()
		switch id {
		case "GHSA-flaky":
			if n <= 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				return false
			}
		case "GHSA-dead":
			w.WriteHeader(http.StatusTooManyRequests)
			return false
		case "GHSA-gone":
			http.NotFound(w, nil)
			return false
		}
		return true
	})
	rows := []model.Row{
		{Type: "npm", Name: "qs", Version: "6.11.0", Agreement: "single"},
		{Type: "npm", Name: "ms", Version: "2.1.3", Agreement: "all"},
		{Type: "npm", Name: "gone", Version: "1.0.0", Agreement: "all"},
		{Type: "npm", Name: "lodash", Version: "4.17.21", Agreement: "all"},
	}
	c := New(srv.URL, "", 0)
	c.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	st, err := c.Enrich(context.Background(), rows, []int{0, 1, 2, 3}, purlOf, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if calls["GHSA-flaky"] != 3 || calls["GHSA-dead"] != 3 || calls["GHSA-gone"] != 1 || calls["GHSA-ok"] != 1 {
		t.Fatalf("attempts: %v", calls)
	}
	if st.Advisories != 4 || st.Scored != 2 || st.DetailsCapped != 2 || st.DetailsFailed != 2 {
		t.Fatalf("stats: %+v", st)
	}
	if rows[0].Vulns[0].Severity != "HIGH" || rows[3].Vulns[0].Severity != "HIGH" {
		t.Fatalf("retried/ok advisories should be scored: %+v %+v", rows[0].Vulns, rows[3].Vulns)
	}
	if rows[1].Vulns[0].Severity != "UNKNOWN" || rows[2].Vulns[0].Severity != "UNKNOWN" {
		t.Fatalf("failed advisories should stay UNKNOWN: %+v %+v", rows[1].Vulns, rows[2].Vulns)
	}
}

// A transport failure (connection refused) is retried too, and a run whose
// details all fail still returns the IDs with every advisory counted.
func TestEnrichTransportFailureIsRetriedThenCounted(t *testing.T) {
	srv := fakeOSV(t, func(string) []string { return []string{"GHSA-1"} }, func(http.ResponseWriter, string) bool { return true })
	c := New(srv.URL, "", 0)
	c.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	// Detail fetches go to a port nobody listens on; the batch still works.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	var attempts int32
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			atomic.AddInt32(&attempts, 1)
			r.URL.Host = strings.TrimPrefix(dead.URL, "http://")
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	rows := []model.Row{{Type: "npm", Name: "qs", Version: "6.11.0", Agreement: "single"}}
	st, err := c.Enrich(context.Background(), rows, []int{0}, purlOf, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
	if st.Advisories != 1 || st.Scored != 0 || st.DetailsCapped != 1 || st.DetailsFailed != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if len(rows[0].Vulns) != 1 || rows[0].Vulns[0].ID != "GHSA-1" || rows[0].Vulns[0].Severity != "UNKNOWN" || rows[0].MaxSev != "UNKNOWN" {
		t.Fatalf("row: %+v", rows[0])
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The cap counts distinct advisories, not row/advisory pairs: one advisory on
// three rows plus a second advisory fit under MaxDetails=2, and MaxDetails=1
// leaves the second one capped.
func TestEnrichCapCountsDistinctIDs(t *testing.T) {
	var detailCalls int32
	srv := fakeOSV(t, func(purl string) []string {
		if strings.Contains(purl, "/extra@") {
			return []string{"GHSA-2"}
		}
		return []string{"GHSA-1"}
	}, func(http.ResponseWriter, string) bool { atomic.AddInt32(&detailCalls, 1); return true })
	mk := func() []model.Row {
		return []model.Row{
			{Type: "npm", Name: "a", Version: "1", Agreement: "all"},
			{Type: "npm", Name: "b", Version: "1", Agreement: "all"},
			{Type: "npm", Name: "c", Version: "1", Agreement: "all"},
			{Type: "npm", Name: "extra", Version: "1", Agreement: "all"},
		}
	}
	c := New(srv.URL, "", 0)
	c.MaxDetails = 2
	rows := mk()
	st, err := c.Enrich(context.Background(), rows, []int{0, 1, 2, 3}, purlOf, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if detailCalls != 2 || st.Advisories != 2 || st.Scored != 2 || st.DetailsCapped != 0 {
		t.Fatalf("MaxDetails=2: calls=%d stats=%+v", detailCalls, st)
	}
	for _, r := range rows {
		if r.Vulns[0].Severity != "HIGH" {
			t.Fatalf("%s should be scored: %+v", r.Name, r.Vulns)
		}
	}
	detailCalls = 0
	c.MaxDetails = 1
	rows = mk()
	st, err = c.Enrich(context.Background(), rows, []int{0, 1, 2, 3}, purlOf, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if detailCalls != 1 || st.Advisories != 2 || st.Scored != 1 || st.DetailsCapped != 1 || st.DetailsFailed != 0 {
		t.Fatalf("MaxDetails=1: calls=%d stats=%+v", detailCalls, st)
	}
	if rows[0].Vulns[0].Severity != "HIGH" || rows[3].Vulns[0].Severity != "UNKNOWN" {
		t.Fatalf("rows: %+v %+v", rows[0].Vulns, rows[3].Vulns)
	}
}
