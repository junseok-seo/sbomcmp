package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
