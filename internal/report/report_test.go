package report

import (
	"strings"
	"testing"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

func TestVulnStatusLine(t *testing.T) {
	res := &model.Result{
		Rows: []model.Row{
			{Key: "npm/a@1", Agreement: "single", Vulns: []model.Vuln{{ID: "CVE-1", Severity: "HIGH", KEV: true, EPSS: 0.3}}, MaxSev: "HIGH"},
			{Key: "npm/b@1", Agreement: "single", Signals: []model.Signal{{Kind: "slopsquat", Level: "refuse"}}},
		},
		MCP:  []model.MCPServer{{Name: "fs", Registry: &model.MCPRegistry{TrustTier: "official"}}, {Name: "x", Registry: &model.MCPRegistry{TrustTier: "unverified"}}},
		Vuln: model.VulnMeta{Enabled: true, Source: "vdb", Anonymous: true, Queried: 1168, Answered: 50},
	}
	got := VulnStatus(res)
	for _, want := range []string{"vdb (anonymous)", "answered **50 of 1168**", "1 KEV row", "1 row with EPSS ≥ 10%", "1 slopsquat signal", "1 MCP registry hit", "export VDB_API_KEY=…"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}

	res.Vuln = model.VulnMeta{Enabled: true, Source: "vdb", Queried: 10, Answered: 10}
	res.Rows[0].Vulns[0].KEV, res.Rows[0].Vulns[0].EPSS = false, 0
	res.Rows[1].Signals = nil
	res.MCP = nil
	got = VulnStatus(res)
	if !strings.Contains(got, "vdb (keyed) · answered 10 of 10 · no VDB-only signals in this project") || strings.Contains(got, "VDB_API_KEY") {
		t.Fatalf("keyed complete: %q", got)
	}

	res.Vuln = model.VulnMeta{Enabled: true, Source: "osv", Queried: 40, Answered: 40, DetailsCapped: 3}
	got = VulnStatus(res)
	if got != "Vulnerability data: osv · answered 40 of 40 · 3 advisories unscored (OSV detail cap), shown as UNKNOWN" {
		t.Fatalf("osv capped: %q", got)
	}

	res.Vuln = model.VulnMeta{Source: "none"}
	if got = VulnStatus(res); !strings.Contains(got, "none (disabled)") {
		t.Fatalf("none: %q", got)
	}
}

func TestMarkdownEPSSColumnAndOrder(t *testing.T) {
	res := &model.Result{
		Target:     "demo",
		Generators: []model.GeneratorRun{{Name: "syft", Available: true}, {Name: "trivy", Available: true}},
		Rows: []model.Row{
			{Key: "npm/crit@1", Agreement: "single", FoundBy: []string{"syft"}, Vulns: []model.Vuln{{ID: "CVE-C", Severity: "CRITICAL", EPSS: 0.01}}, MaxSev: "CRITICAL"},
			{Key: "npm/kev@1", Agreement: "single", FoundBy: []string{"trivy"}, Vulns: []model.Vuln{{ID: "CVE-K", Severity: "MEDIUM", KEV: true, EPSS: 0.5}}, MaxSev: "MEDIUM"},
			{Key: "npm/epss@1", Agreement: "single", FoundBy: []string{"trivy"}, Vulns: []model.Vuln{{ID: "CVE-E", Severity: "HIGH", EPSS: 0.2}}, MaxSev: "HIGH"},
		},
		Summaries:      []model.ToolSummary{{Name: "syft"}, {Name: "trivy"}},
		Recommendation: model.Recommendation{Primary: "syft"},
		Vuln:           model.VulnMeta{Enabled: true, Source: "vdb", Queried: 3, Answered: 3},
	}
	md := Markdown(res, 50)
	if !strings.Contains(md, "| Component | Found by | Severity | EPSS | Vulns / signals |") {
		t.Fatalf("EPSS column missing:\n%s", md)
	}
	k, e, c := strings.Index(md, "npm/kev@1"), strings.Index(md, "npm/epss@1"), strings.Index(md, "npm/crit@1")
	if !(k < e && e < c) {
		t.Fatalf("expected KEV, then EPSS, then severity order:\n%s", md)
	}
	if !strings.Contains(md, "| MEDIUM | 50.0% | CVE-K (KEV) |") {
		t.Fatalf("EPSS cell:\n%s", md)
	}
	if !strings.Contains(md, "Vulnerability data: vdb (keyed) · answered 3 of 3") {
		t.Fatalf("status line missing:\n%s", md)
	}

	// Without EPSS data the table keeps its original shape.
	for i := range res.Rows {
		for j := range res.Rows[i].Vulns {
			res.Rows[i].Vulns[j].EPSS = 0
		}
	}
	md = Markdown(res, 50)
	if strings.Contains(md, "| EPSS |") {
		t.Fatalf("EPSS column must be omitted without data:\n%s", md)
	}
}
