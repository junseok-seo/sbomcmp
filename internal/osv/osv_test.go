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
	err := c.Enrich(context.Background(), rows, []int{0, 1}, func(r model.Row) string { return "pkg:" + r.Type + "/" + r.Name + "@" + r.Version }, "osv")
	if err != nil {
		t.Fatal(err)
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
