package cdx

import "testing"

func TestParseCycloneDXNestedAndScope(t *testing.T) {
	doc := `{
	  "bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[
	    {"type":"library","name":"a","version":"1","purl":"pkg:npm/a@1",
	     "properties":[{"name":"cdx:npm:package:development","value":"true"}],
	     "components":[{"type":"library","name":"b","version":"2","purl":"pkg:npm/b@2"}]},
	    {"type":"application","name":"go.mod"},
	    {"type":"library","name":"example.com/root","purl":"pkg:golang/example.com/root"},
	    {"type":"file","name":"/bin/sh"},
	    {"type":"library","name":"a","version":"1","purl":"pkg:npm/a@1?foo=bar"}
	  ]}`
	comps, format, skipped, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if format != "cyclonedx-1.5" || skipped != 1 {
		t.Fatalf("format %q skipped %d", format, skipped)
	}
	if len(comps) != 2 {
		t.Fatalf("expected 2 components (dedupe + skip structure nodes), got %d: %+v", len(comps), comps)
	}
	if comps[0].Scope != "dev" {
		t.Fatalf("expected dev scope from cdxgen property, got %q", comps[0].Scope)
	}
}

func TestParseDocRoot(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6",
	  "metadata":{"component":{"type":"application","name":"sample-app","version":"1.0.0","purl":"pkg:npm/sample-app@1.0.0"}},
	  "components":[{"type":"library","name":"a","version":"1","purl":"pkg:npm/a@1"}]}`
	d, err := ParseDoc([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if d.Root == nil || d.Root.NameKey != "npm/sample-app" || d.Root.Version != "1.0.0" || len(d.Components) != 1 {
		t.Fatalf("root not parsed: %+v", d)
	}
	// Trivy's root is a path with no purl and no version: not a package.
	d, _ = ParseDoc([]byte(`{"bomFormat":"CycloneDX","metadata":{"component":{"type":"application","name":"src/project"}},"components":[]}`))
	if d.Root != nil {
		t.Fatalf("path root must be ignored: %+v", d.Root)
	}
}

func TestParseSPDXFallback(t *testing.T) {
	doc := `{"SPDXID":"SPDXRef-DOCUMENT","packages":[
	  {"name":"lodash","versionInfo":"4.17.21","licenseConcluded":"MIT",
	   "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.21"}]}]}`
	comps, format, _, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if format != "spdx" || len(comps) != 1 || comps[0].Key != "npm/lodash@4.17.21" || comps[0].Licenses[0] != "MIT" {
		t.Fatalf("bad spdx parse: %s %+v", format, comps)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, _, _, err := Parse([]byte(`{"hello":"world"}`)); err == nil {
		t.Fatal("expected error")
	}
}
