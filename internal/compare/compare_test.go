package compare

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/junseok-seo/sbomcmp/internal/cdx"
	"github.com/junseok-seo/sbomcmp/internal/model"
)

// loadMock runs the mock generator scripts' embedded documents through the real parser.
func loadMock(t *testing.T) []model.GeneratorRun {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "mock-bin")
	var runs []model.GeneratorRun
	for _, name := range []string{"syft", "cdxgen", "trivy"} {
		src, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		// Extract the heredoc body between <<'JSON' and JSON.
		s := string(src)
		start := indexAfter(s, "<<'JSON'\n")
		end := lastIndexBefore(s, "\nJSON\n")
		if start < 0 || end < 0 || end < start {
			t.Fatalf("%s: heredoc not found", name)
		}
		comps, _, _, err := cdx.Parse([]byte(s[start:end]))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		runs = append(runs, model.GeneratorRun{Name: name, Available: true, Components: comps, Types: map[string]int{}})
	}
	return runs
}

func indexAfter(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i + len(sub)
		}
	}
	return -1
}

func lastIndexBefore(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func rowByKey(rows []model.Row, key string) *model.Row {
	for i := range rows {
		if rows[i].Key == key {
			return &rows[i]
		}
	}
	return nil
}

func TestBuildCollapsesIdentifierVariants(t *testing.T) {
	rows, pairs := Build(loadMock(t))

	// Flask_Login (syft) / flask-login (cdxgen, trivy) → one row, all three.
	if r := rowByKey(rows, "pypi/flask-login@0.6.3"); r == nil || r.Agreement != "all" {
		t.Fatalf("flask-login not collapsed: %+v", r)
	}
	// %40babel (syft) / @babel (cdxgen) → one row.
	if r := rowByKey(rows, "npm/@babel/runtime@7.24.0"); r == nil || len(r.FoundBy) != 2 {
		t.Fatalf("@babel/runtime not collapsed: %+v", r)
	}
	// Go v-prefix: syft/trivy "v1.8.1", cdxgen "1.8.1" → one row.
	if r := rowByKey(rows, "golang/github.com/gorilla/mux@1.8.1"); r == nil || r.Agreement != "all" {
		t.Fatalf("gorilla/mux not collapsed: %+v", r)
	}
	// Trivy's purl-less application nodes must not become rows.
	for _, r := range rows {
		if r.Type == "unknown" {
			t.Fatalf("unexpected unknown row: %s", r.Key)
		}
	}
	// Version drift: pyyaml 6.0 (trivy) vs 6.0.1 (others) → two rows with version-mismatch reasons.
	r601 := rowByKey(rows, "pypi/pyyaml@6.0.1")
	r60 := rowByKey(rows, "pypi/pyyaml@6.0")
	if r601 == nil || r60 == nil {
		t.Fatal("expected both pyyaml rows")
	}
	if len(r60.Reasons) == 0 || !contains(r60.Reasons[0], "version-mismatch") {
		t.Fatalf("expected version-mismatch reason, got %v", r60.Reasons)
	}
	// Ecosystem-coverage reason: trivy saw no npm.
	if r := rowByKey(rows, "npm/express@4.19.2"); r == nil || !contains(r.Reasons[0], "ecosystem-coverage: trivy") {
		t.Fatalf("expected ecosystem-coverage reason for express, got %+v", r)
	}
	// Pairwise sanity.
	if len(pairs) != 3 {
		t.Fatalf("expected 3 pairs, got %d", len(pairs))
	}
	for _, p := range pairs {
		if p.A == "cdxgen" && p.B == "trivy" && len(p.VersionDisagree) != 1 {
			t.Fatalf("expected 1 version disagreement cdxgen/trivy, got %v", p.VersionDisagree)
		}
	}
}

func TestFinalizeRecommendsByCoverageAndVulns(t *testing.T) {
	runs := loadMock(t)
	rows, pairs := Build(runs)
	// Inject vulnerabilities on cdxgen-only rows.
	for i := range rows {
		switch rows[i].Key {
		case "npm/qs@6.11.0", "pypi/werkzeug@3.0.1":
			rows[i].Vulns = []model.Vuln{{ID: "X", Severity: "HIGH"}}
			rows[i].MaxSev = "HIGH"
		}
	}
	res := &model.Result{Generators: runs, Rows: rows, Pairs: pairs, Vuln: model.VulnMeta{Enabled: true}}
	Finalize(res)
	if res.Recommendation.Primary != "cdxgen" {
		t.Fatalf("expected cdxgen primary, got %s", res.Recommendation.Primary)
	}
	var cdx *model.ToolSummary
	for i := range res.Summaries {
		if res.Summaries[i].Name == "cdxgen" {
			cdx = &res.Summaries[i]
		}
	}
	if cdx == nil || cdx.UniqueCritHigh != 2 {
		t.Fatalf("expected 2 unique crit/high for cdxgen, got %+v", cdx)
	}
	if res.Union != len(rows) || res.Intersection == 0 {
		t.Fatalf("bad union/intersection: %d/%d", res.Union, res.Intersection)
	}
}

func contains(s, sub string) bool { return indexAfter(s, sub) >= 0 }

func TestFinalizeExplainsIncompleteEnrichment(t *testing.T) {
	has := func(cs []string, sub string) bool {
		for _, c := range cs {
			if contains(c, sub) {
				return true
			}
		}
		return false
	}
	run := func(v model.VulnMeta) []string {
		runs := loadMock(t)
		rows, pairs := Build(runs)
		res := &model.Result{Generators: runs, Rows: rows, Pairs: pairs, Vuln: v}
		Finalize(res)
		return res.Recommendation.Caveats
	}

	// Anonymous VDB quota: partial coverage, with the fix.
	cs := run(model.VulnMeta{Enabled: true, Source: "vdb", Anonymous: true, Queried: 1168, Answered: 50})
	if !has(cs, "covered only 50 of 1168 disagreement rows (VDB anonymous quota — set VDB_API_KEY for full coverage)") {
		t.Fatalf("missing coverage caveat: %v", cs)
	}
	if has(cs, "offline or disabled") {
		t.Fatalf("generic caveat must be dropped: %v", cs)
	}

	// OSV detail cap.
	cs = run(model.VulnMeta{Enabled: true, Source: "osv", Queried: 40, Answered: 40, DetailsCapped: 12})
	if !has(cs, "12 advisories were not scored (OSV detail cap); shown as UNKNOWN") {
		t.Fatalf("missing detail-cap caveat: %v", cs)
	}
	if has(cs, "offline or disabled") || has(cs, "covered only") {
		t.Fatalf("unexpected caveats: %v", cs)
	}

	// Complete run: no vulnerability caveat at all.
	cs = run(model.VulnMeta{Enabled: true, Source: "osv", Queried: 40, Answered: 40})
	if has(cs, "Vulnerability weighting") || has(cs, "advisories were not scored") {
		t.Fatalf("unexpected caveat on a complete run: %v", cs)
	}

	// Disabled or failed: the generic caveat stays.
	cs = run(model.VulnMeta{Source: "osv", Error: "dial tcp: no route"})
	if !has(cs, "not applied: dial tcp: no route") {
		t.Fatalf("missing generic caveat: %v", cs)
	}
}

func TestFinalizeBuildsActions(t *testing.T) {
	gens := []model.GeneratorRun{{Name: "syft", Available: true}, {Name: "trivy", Available: true}}
	row := func(key string) model.Row {
		return model.Row{Key: key, Type: "npm", Name: key, Agreement: "single", FoundBy: []string{"syft"},
			Cells: map[string]model.Cell{"syft": {Found: true}, "trivy": {}}}
	}
	mal := row("npm/evil@1.0.0")
	mal.Vulns = []model.Vuln{{ID: "MAL-2025-1", Malicious: true, Severity: "CRITICAL"}}
	kev := row("npm/kev@2.0.0")
	kev.Vulns = []model.Vuln{{ID: "CVE-K", Severity: "MEDIUM", KEV: true, EPSS: 0.42, Fixed: "2.0.1"}}
	epssLow := row("npm/epss-low@1.0.0")
	epssLow.Vulns = []model.Vuln{{ID: "CVE-E1", Severity: "HIGH", EPSS: 0.12, Fixed: "1.0.9"}}
	epssHigh := row("npm/epss-high@1.0.0")
	epssHigh.Vulns = []model.Vuln{{ID: "CVE-E2", Severity: "LOW", EPSS: 0.55}}
	quiet := row("npm/quiet@1.0.0")
	quiet.Vulns = []model.Vuln{{ID: "CVE-Q", Severity: "CRITICAL", EPSS: 0.01}}
	slop := row("npm/requests-toolkit-pro@1.2.0")
	slop.Signals = []model.Signal{{Kind: "slopsquat", Level: "refuse", Source: "vdb", Message: "no such name on npm"}}
	own := row("npm/our-internal-lib@0.1.0")
	own.FirstParty = true
	own.Signals = []model.Signal{{Kind: "slopsquat", Level: "refuse", Source: "vdb"}}

	servers := []model.MCPServer{
		{Name: "filesystem", Registry: &model.MCPRegistry{TrustTier: "official", Scopes: []string{"fs:read", "fs:write"}}},
		{Name: "browser", Registry: &model.MCPRegistry{TrustTier: "community", Scopes: []string{"net:outbound", "exec"}, ScopeDrift: "+exec"}},
		{Name: "github", Registry: &model.MCPRegistry{TrustTier: "unverified"},
			Signals: []model.Signal{{Kind: "mcp", Level: "warn", Message: "unverified publisher"}}},
		{Name: "danger", Registry: &model.MCPRegistry{TrustTier: "official"},
			Signals: []model.Signal{{Kind: "advisory", Level: "refuse", Message: "CVE-X (critical) affects 1.0"}}},
	}
	// Row order on input is deliberately scrambled; the action order must not follow it.
	res := &model.Result{Generators: gens, Rows: []model.Row{quiet, slop, epssLow, own, kev, epssHigh, mal}, MCP: servers,
		Vuln: model.VulnMeta{Enabled: true, Source: "vdb", Queried: 7, Answered: 7}}
	Finalize(res)

	var got []string
	for _, a := range res.Actions {
		got = append(got, a.Kind+" "+a.Level+" "+a.Key+" → "+a.Fix)
	}
	want := []string{
		"malicious refuse npm/evil@1.0.0 → remove",
		"kev refuse npm/kev@2.0.0 → upgrade to 2.0.1",
		"epss warn npm/epss-high@1.0.0 → upgrade (no fixed version published yet)",
		"epss warn npm/epss-low@1.0.0 → upgrade to 1.0.9",
		"slopsquat refuse npm/requests-toolkit-pro@1.2.0 → check the name",
		"mcp warn browser → pin and review the server",
		"mcp refuse danger → pin and review the server",
	}
	if len(got) != len(want) {
		t.Fatalf("actions:\n got %q\nwant %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("action %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
	if res.ActionTotal != len(want) {
		t.Fatalf("ActionTotal %d, want %d", res.ActionTotal, len(want))
	}
	if a := res.Actions[1]; !contains(a.Message, "CVE-K") || !contains(a.Message, "KEV") || !contains(a.Message, "EPSS 42%") {
		t.Fatalf("KEV message: %q", a.Message)
	}
	if a := res.Actions[5]; !contains(a.Message, "trust community") || !contains(a.Message, "scopes net:outbound exec") || !contains(a.Message, "scope drift +exec") {
		t.Fatalf("MCP message: %q", a.Message)
	}
	if a := res.Actions[4]; a.Message != "no such name on npm" {
		t.Fatalf("slopsquat message should carry the signal text: %q", a.Message)
	}

	// The slopsquat row gets a reason the Why column can show; first-party does not.
	slopRow := rowByKey(res.Rows, "npm/requests-toolkit-pro@1.2.0")
	if len(slopRow.Reasons) != 1 || slopRow.Reasons[0] != "hallucinated-name: not on the npm registry (VDB); tools differ on unresolvable dependencies" {
		t.Fatalf("slopsquat reason: %v", slopRow.Reasons)
	}
	if r := rowByKey(res.Rows, "npm/our-internal-lib@0.1.0"); len(r.Reasons) != 0 {
		t.Fatalf("first-party row must not get the reason: %v", r.Reasons)
	}
	// Finalize is idempotent for the reason.
	Finalize(res)
	if n := len(rowByKey(res.Rows, "npm/requests-toolkit-pro@1.2.0").Reasons); n != 1 {
		t.Fatalf("reason duplicated: %d", n)
	}

	if got := res.ActionsAtLeast("refuse"); len(got) != 4 {
		t.Fatalf("ActionsAtLeast(refuse) = %d, want 4", len(got))
	}
	if got := res.ActionsAtLeast("warn"); len(got) != 7 {
		t.Fatalf("ActionsAtLeast(warn) = %d, want 7", len(got))
	}
	if got := res.ActionsAtLeast("none"); got != nil {
		t.Fatalf("ActionsAtLeast(none) = %v", got)
	}
}

func TestActionsCap(t *testing.T) {
	var rows []model.Row
	for i := 0; i < model.MaxActions+5; i++ {
		rows = append(rows, model.Row{Key: "npm/p" + string(rune('a'+i%26)) + "@1", Type: "npm", Agreement: "single",
			Vulns: []model.Vuln{{ID: "CVE", EPSS: 0.2 + float64(i)/100}}})
	}
	// One malicious row buried at the end must still come first.
	rows = append(rows, model.Row{Key: "npm/evil@1", Type: "npm", Agreement: "single", Vulns: []model.Vuln{{ID: "MAL", Malicious: true}}})
	acts, total := actions(rows, nil)
	if len(acts) != model.MaxActions || total != model.MaxActions+6 {
		t.Fatalf("len %d total %d", len(acts), total)
	}
	if acts[0].Kind != "malicious" || acts[1].Key != rows[model.MaxActions+4].Key {
		t.Fatalf("order: %+v %+v", acts[0], acts[1])
	}
}

func TestDemoFixtureActions(t *testing.T) {
	// The demo path: mock generators + the offline fixture (which stands in
	// for VDB and therefore sets vdbExtras).
	runs := loadMock(t)
	rows, pairs := Build(runs)
	for i := range rows {
		if rows[i].Key == "npm/requests-toolkit-pro@1.2.0" {
			rows[i].Signals = []model.Signal{{Kind: "slopsquat", Level: "refuse", Source: "vdb", Message: "no such name on the npm registry"}}
		}
	}
	res := &model.Result{Generators: runs, Rows: rows, Pairs: pairs,
		MCP: []model.MCPServer{{Name: "browser", Package: "pkg:pypi/mcp-server-browser",
			Registry: &model.MCPRegistry{TrustTier: "community", Scopes: []string{"net:outbound", "exec"}, ScopeDrift: "+exec (2026-09-12)"}}},
		Vuln: model.VulnMeta{Enabled: true, Source: "fixture", VDBExtras: true}}
	Finalize(res)
	if len(res.Actions) != 2 || res.Actions[0].Kind != "slopsquat" || res.Actions[1].Kind != "mcp" || res.Actions[1].Key != "browser" {
		t.Fatalf("demo actions: %+v", res.Actions)
	}
	if !res.VDBSignalsActive() {
		t.Fatal("fixture with vdbExtras must count as VDB-active")
	}
}

func TestInstalledOnlyRowsStayOutOfActions(t *testing.T) {
	cells := func(paths ...[]string) map[string]model.Cell {
		m := map[string]model.Cell{}
		for i, p := range paths {
			m[fmt.Sprintf("t%d", i)] = model.Cell{Found: true, Paths: p}
		}
		return m
	}
	if !installedOnly(cells([]string{"/web/node_modules/x/package.json"}, []string{"/app/.venv/lib/site-packages/x"})) {
		t.Fatal("all paths inside installed trees must classify as installed")
	}
	if installedOnly(cells([]string{"/web/node_modules/x/package.json"}, []string{"/web/package-lock.json"})) {
		t.Fatal("a lockfile sighting makes it a declared dependency")
	}
	if installedOnly(cells(nil, nil)) {
		t.Fatal("no evidence at all must not classify as installed")
	}
	if installedOnly(cells([]string{"/web/node_modules/x/package.json"}, nil)) != true {
		t.Fatal("a tool without paths neither confirms nor denies")
	}
	rows := []model.Row{
		{Key: "npm/x@1", Type: "npm", Installed: true, Vulns: []model.Vuln{{ID: "K", KEV: true, Severity: "HIGH"}}, MaxSev: "HIGH"},
		{Key: "npm/y@1", Type: "npm", Vulns: []model.Vuln{{ID: "K2", KEV: true, Severity: "HIGH"}}, MaxSev: "HIGH"},
	}
	acts, total := actions(rows, nil)
	if total != 1 || len(acts) != 1 || acts[0].Key != "npm/y@1" {
		t.Fatalf("installed row must not produce an action: %+v", acts)
	}
}

func TestInstalledCaveatSurvivesFinalize(t *testing.T) {
	runs := loadMock(t)
	rows, pairs := Build(runs)
	rows = append(rows, model.Row{Key: "generic/ffmpeg@61.7.100", NameKey: "generic/ffmpeg", Type: "generic", Name: "ffmpeg", Version: "61.7.100",
		Cells: map[string]model.Cell{"syft": {Found: true, Paths: []string{"/node_modules/@remotion/x/libavformat.dylib"}}}, FoundBy: []string{"syft"}, Agreement: "single",
		Installed: true, Vulns: []model.Vuln{{ID: "CVE-X", Severity: "HIGH"}}, MaxSev: "HIGH"})
	res := &model.Result{Generators: runs, Rows: rows, Pairs: pairs, Vuln: model.VulnMeta{Enabled: true}}
	Finalize(res)
	found := false
	for _, c := range res.Recommendation.Caveats {
		if contains(c, "installed trees") {
			found = true
		}
	}
	if !found {
		t.Fatalf("installed caveat missing: %v", res.Recommendation.Caveats)
	}
	for _, a := range res.Actions {
		if a.Key == "generic/ffmpeg@61.7.100" {
			t.Fatal("installed row must not be an action")
		}
	}
}
