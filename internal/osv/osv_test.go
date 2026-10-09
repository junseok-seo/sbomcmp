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
				"affected": []any{map[string]any{"ranges": []any{map[string]any{"events": []map[string]string{{"introduced": "0"}, {"fixed": "6.11.1"}}}}}},
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
