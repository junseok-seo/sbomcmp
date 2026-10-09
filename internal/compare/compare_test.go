package compare

import (
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
