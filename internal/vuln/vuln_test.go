package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

func TestResolve(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{}, "osv"},
		{Config{VDBKey: "k"}, "vdb"},
		{Config{VDBKey: "k", Source: "osv"}, "osv"},
		{Config{Source: "vdb"}, "vdb"},
		{Config{Source: "none", VDBKey: "k"}, "none"},
		{Config{Fixture: "x.json", VDBKey: "k"}, "fixture"},
	}
	for _, c := range cases {
		if got := c.cfg.Resolve(); got != c.want {
			t.Errorf("%+v: got %s want %s", c.cfg, got, c.want)
		}
	}
}

func TestFixtureEnrichment(t *testing.T) {
	fx := filepath.Join("..", "..", "testdata", "fixtures", "vulns.json")
	rows := []model.Row{
		{Type: "npm", Name: "qs", Version: "6.11.0", Agreement: "single"},
		{Type: "golang", Namespace: "golang.org/x", Name: "net", Version: "0.10.0", Agreement: "single"},
		{Type: "npm", Name: "requests-toolkit-pro", Version: "1.2.0", Agreement: "partial"},
		{Type: "npm", Name: "express", Version: "4.19.2", Agreement: "all"},
	}
	var meta model.VulnMeta
	Enrich(context.Background(), Config{Fixture: fx, OnlyDisagreements: true}, rows, &meta)
	if !meta.Enabled || meta.Source != "fixture" || meta.Queried != 3 || meta.Answered != 3 || meta.Hits != 2 || !meta.Complete() {
		t.Fatalf("meta: %+v", meta)
	}
	if rows[0].MaxSev != "HIGH" || rows[1].MaxSev != "HIGH" || len(rows[1].Vulns) != 2 {
		t.Fatalf("rows: %+v %+v", rows[0], rows[1])
	}
	if len(rows[2].Signals) != 1 || rows[2].Signals[0].Kind != "slopsquat" || !meta.VDBExtras {
		t.Fatalf("signal: %+v", rows[2])
	}
	if QueryPurl(rows[1]) != "pkg:golang/golang.org/x/net@v0.10.0" {
		t.Fatalf("query purl: %s", QueryPurl(rows[1]))
	}

	servers := []model.MCPServer{{Name: "filesystem", Package: "pkg:npm/%40modelcontextprotocol/server-filesystem"}, {Name: "github", Package: "pkg:npm/github-mcp-server"}, {Name: "remote", URL: "http://x"}}
	EnrichMCP(context.Background(), Config{Fixture: fx}, servers, &meta)
	if servers[0].Registry == nil || servers[0].Registry.TrustTier != "official" {
		t.Fatalf("filesystem registry: %+v", servers[0].Registry)
	}
	if servers[1].Registry == nil || servers[1].Registry.TrustTier != "unverified" || len(servers[1].Signals) != 1 {
		t.Fatalf("github registry: %+v", servers[1])
	}
}

// Anonymous VDB answers one batch and then returns 429: the scan keeps the
// answered rows, Answered < Queried, and the quota is explained.
func TestVDBPartialCoverageIsRecorded(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Packages []string `json:"packages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if calls > 1 {
			w.WriteHeader(429)
			w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		var results []map[string]any
		for _, p := range req.Packages {
			results = append(results, map[string]any{"input": p, "purl": p, "risk": "high",
				"vulnerabilities":       []map[string]any{{"id": "CVE-2024-1", "severity_bucket": "high", "severity_score": 8.1, "kev": true, "epss": 0.42}},
				"vulnerabilities_total": 1})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results,
			"anonymous": map[string]any{"authenticated": false, "limit_per_hour": 20, "remaining": 0}})
	}))
	defer srv.Close()

	var rows []model.Row
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		rows = append(rows, model.Row{Type: "npm", Name: n, Version: "1.0.0", Agreement: "single"})
	}
	var meta model.VulnMeta
	Enrich(context.Background(), Config{Source: "vdb", VDBEndpoint: srv.URL}, rows, &meta)
	if !meta.Enabled || meta.Source != "vdb" || !meta.Anonymous {
		t.Fatalf("meta: %+v", meta)
	}
	if meta.Queried != 7 || meta.Answered != 5 || meta.Hits != 5 || meta.Complete() {
		t.Fatalf("coverage: %+v", meta)
	}
	if !strings.Contains(meta.Note, "answered 5 of 7") || !strings.Contains(meta.Note, "anonymous quota") {
		t.Fatalf("note: %q", meta.Note)
	}
	if !rows[0].Vulns[0].KEV || rows[0].Vulns[0].EPSS != 0.42 || rows[0].MaxSev != "HIGH" {
		t.Fatalf("row 0: %+v", rows[0].Vulns)
	}
	if len(rows[6].Vulns) != 0 {
		t.Fatalf("row past the quota must stay unanswered: %+v", rows[6])
	}
}

// OSV: the batch query answers every row, so Answered == Queried even when
// the detail cap leaves advisories unscored.
func TestOSVAnsweredAndDetailsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []json.RawMessage `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			var res []any
			for i := range req.Queries {
				res = append(res, map[string]any{"vulns": []map[string]string{{"id": "GHSA-" + string(rune('a'+i))}}})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		default:
			json.NewEncoder(w).Encode(map[string]any{"id": "x", "database_specific": map[string]string{"severity": "LOW"}})
		}
	}))
	defer srv.Close()
	rows := []model.Row{
		{Type: "npm", Name: "a", Version: "1", Agreement: "single"},
		{Type: "npm", Name: "b", Version: "1", Agreement: "single"},
	}
	var meta model.VulnMeta
	Enrich(context.Background(), Config{Source: "osv", OSVEndpoint: srv.URL}, rows, &meta)
	if !meta.Enabled || meta.Queried != 2 || meta.Answered != 2 || meta.DetailsCapped != 0 || meta.Hits != 2 {
		t.Fatalf("meta: %+v", meta)
	}
}
