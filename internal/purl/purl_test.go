package purl

import "testing"

func TestNormalizeCollapses(t *testing.T) {
	cases := []struct {
		a, b string
		same bool
	}{
		// Go: v-prefix and namespace split
		{"pkg:golang/github.com/gorilla/mux@v1.8.1", "pkg:golang/github.com/gorilla/mux@1.8.1", true},
		{"pkg:golang/github.com/gorilla/mux@v1.8.1", "pkg:golang/github.com/gorilla%2Fmux@v1.8.1", true},
		// PyPI: separators + case
		{"pkg:pypi/Flask_Login@0.6.3", "pkg:pypi/flask-login@0.6.3", true},
		{"pkg:pypi/zope.interface@6.0", "pkg:pypi/zope-interface@6.0", true},
		// npm: scope encoding
		{"pkg:npm/%40babel/core@7.24.0", "pkg:npm/@babel/core@7.24.0", true},
		{"pkg:npm/@babel/core@7.24.0", "pkg:npm/babel/core@7.24.0", true},
		// qualifiers dropped
		{"pkg:deb/debian/zlib1g@1.2.13?arch=amd64&distro=debian-12", "pkg:deb/debian/zlib1g@1:1.2.13", true},
		// different version is different
		{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.20", false},
		// type alias
		{"pkg:go/github.com/x/y@v1", "pkg:golang/github.com/x/y@v1", true},
	}
	for _, c := range cases {
		ka := Key(Normalize(Parse(c.a)))
		kb := Key(Normalize(Parse(c.b)))
		if (ka == kb) != c.same {
			t.Errorf("%s vs %s: got %q / %q, want same=%v", c.a, c.b, ka, kb, c.same)
		}
	}
}

func TestParseFields(t *testing.T) {
	p := Parse("pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar#sub/path")
	if p.Type != "maven" || p.Namespace != "org.apache.commons" || p.Name != "commons-lang3" || p.Version != "3.12.0" {
		t.Fatalf("bad parse: %+v", p)
	}
	if p.Qualifiers["type"] != "jar" || p.Subpath != "sub/path" {
		t.Fatalf("bad qualifiers/subpath: %+v", p)
	}
}

func TestMalformed(t *testing.T) {
	p := Parse("not-a-purl")
	if p.Type != "unknown" || p.Name != "not-a-purl" {
		t.Fatalf("expected tolerant parse, got %+v", p)
	}
}

func TestStringEncodesSegments(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/@babel/core@7.24.0":                "pkg:npm/%40babel/core@7.24.0",
		"pkg:golang/github.com/gorilla/mux@v1.8.1":  "pkg:golang/github.com/gorilla/mux@1.8.1",
		"pkg:maven/org.apache.commons/lang3@3.12.0": "pkg:maven/org.apache.commons/lang3@3.12.0",
		"pkg:deb/debian/zlib1g@1:1.2.13?arch=amd64": "pkg:deb/debian/zlib1g@1.2.13",
	}
	for in, want := range cases {
		if got := String(Normalize(Parse(in))); got != want {
			t.Errorf("String(%s) = %s, want %s", in, got, want)
		}
	}
	if got := QueryString(Normalize(Parse("pkg:golang/golang.org/x/net@0.10.0"))); got != "pkg:golang/golang.org/x/net@v0.10.0" {
		t.Errorf("QueryString go = %s", got)
	}
}
