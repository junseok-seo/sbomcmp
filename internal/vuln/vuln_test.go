package vuln

import (
	"context"
	"path/filepath"
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
	if !meta.Enabled || meta.Source != "fixture" || meta.Queried != 3 || meta.Hits != 2 {
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
