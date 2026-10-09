package firstparty

import (
	"path/filepath"
	"testing"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

func TestCollectAndMark(t *testing.T) {
	decls := Collect(filepath.Join("..", "..", "testdata", "firstparty"))
	got := map[string]Decl{}
	for _, d := range decls {
		got[d.NameKey] = d
	}
	want := map[string]string{
		"npm/monorepo-root":      "0.0.0",
		"npm/vdb-web":            "0.1.0",
		"cargo/vdb-demo":         "0.1.0",
		"pypi/vdb-api":           "2.0.0", // PEP 503 normalized from VDB_Api
		"golang/example.com/vdb": "",
	}
	for k, v := range want {
		d, ok := got[k]
		if !ok || d.Version != v {
			t.Fatalf("decl %s: want version %q, got %+v (all: %+v)", k, v, d, decls)
		}
	}
	if !got["npm/monorepo-root"].Private {
		t.Fatal("private flag not read")
	}
	if _, ok := got["pypi/ignored-when-project-present"]; ok {
		t.Fatal("[tool.poetry] must not override [project]")
	}

	rows := []model.Row{
		{NameKey: "npm/vdb-web", Version: "0.1.0"},    // first-party
		{NameKey: "npm/vdb-web", Version: "2.3.0"},    // same name, other version: a real dependency
		{NameKey: "cargo/vdb-demo", Version: "0.1.0"}, // workspace member
		{NameKey: "golang/example.com/vdb", Version: "1.0.0"},
		{NameKey: "npm/astro", Version: "5.0.0"},
	}
	root := FromRoot("syft", &model.Component{NameKey: "npm/sample-app", Type: "npm", Version: "1.0.0"})
	rows = append(rows, model.Row{NameKey: "npm/sample-app", Version: "1.0.0"})
	n := Mark(rows, append(decls, *root))
	if n != 4 {
		t.Fatalf("expected 4 first-party rows, got %d: %+v", n, rows)
	}
	if !rows[0].FirstParty || rows[1].FirstParty || !rows[2].FirstParty || !rows[3].FirstParty || rows[4].FirstParty || !rows[5].FirstParty {
		t.Fatalf("marking: %+v", rows)
	}
	if rows[0].FirstPartySource != "packages/web/package.json" || rows[5].FirstPartySource != "syft metadata.component" {
		t.Fatalf("sources: %q %q", rows[0].FirstPartySource, rows[5].FirstPartySource)
	}
}
