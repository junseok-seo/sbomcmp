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

func TestMarkdownActNow(t *testing.T) {
	res := &model.Result{
		Target:         "demo",
		Generators:     []model.GeneratorRun{{Name: "syft", Available: true}},
		Summaries:      []model.ToolSummary{{Name: "syft"}},
		Recommendation: model.Recommendation{Primary: "syft", Reasons: []string{"syft covers 100% of the union."}},
		Vuln:           model.VulnMeta{Enabled: true, Source: "vdb", Queried: 3, Answered: 3},
		Actions: []model.Action{
			{Kind: "malicious", Level: "refuse", Key: "npm/evil@1.0.0", Message: "MAL-1: known malicious release", Fix: "remove"},
			{Kind: "kev", Level: "refuse", Key: "npm/kev@2.0.0", Message: "CVE-K: in CISA KEV", Fix: "upgrade to 2.0.1"},
			{Kind: "mcp", Level: "warn", Key: "browser", Message: "MCP server trust community, scopes exec", Fix: "pin and review the server"},
		},
		ActionTotal: 25,
	}
	md := Markdown(res, 50)
	rec, act, table := strings.Index(md, "syft covers 100%"), strings.Index(md, "**Act now** (25)"), strings.Index(md, "| Tool | Version |")
	if !(rec >= 0 && rec < act && act < table) {
		t.Fatalf("Act now block must sit between the recommendation and the tool table:\n%s", md)
	}
	for _, want := range []string{
		"| 🛑 refuse | `npm/evil@1.0.0` | MAL-1: known malicious release | **remove** |",
		"| 🛑 refuse | `npm/kev@2.0.0` | CVE-K: in CISA KEV | **upgrade to 2.0.1** |",
		"| ⚠️ warn | MCP `browser` | MCP server trust community, scopes exec | **pin and review the server** |",
		"| … | | 22 more | |",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("missing %q in:\n%s", want, md)
		}
	}

	res.Actions, res.ActionTotal = nil, 0
	if md = Markdown(res, 50); !strings.Contains(md, "**Act now:** "+NoActionsLine) {
		t.Fatalf("all-clear line missing:\n%s", md)
	}

	res.Vuln = model.VulnMeta{Enabled: true, Source: "osv", Queried: 3, Answered: 3}
	md = Markdown(res, 50)
	if !strings.Contains(md, "_"+NeedVDBLine+"_") || strings.Contains(md, "Act now") {
		t.Fatalf("osv run must show the need-VDB line only:\n%s", md)
	}

	// A fixture that stands in for VDB (vdbExtras) counts as VDB-active.
	res.Vuln = model.VulnMeta{Enabled: true, Source: "fixture", VDBExtras: true}
	if md = Markdown(res, 50); !strings.Contains(md, NoActionsLine) {
		t.Fatalf("fixture with vdbExtras:\n%s", md)
	}

	lines := ActionLines([]model.Action{{Kind: "mcp", Level: "warn", Key: "browser", Message: "m", Fix: "f"}})
	if len(lines) != 1 || lines[0] != "[warn] MCP browser — m → f" {
		t.Fatalf("ActionLines: %q", lines)
	}
}
