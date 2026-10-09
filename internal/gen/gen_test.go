package gen

import "testing"

func TestNewerThanTested(t *testing.T) {
	cases := []struct {
		installed, tested string
		want              bool
	}{
		{"1.54.1", "1.54", false}, // same minor, patch ignored
		{"1.55.0", "1.54", true},
		{"2.0.0", "1.54", true},
		{"1.53.9", "1.54", false},
		{"v0.76.0", "0.75", true},
		{"0.75.0", "0.75", false},
		{"12.9.0", "12.8", true},
		{"12.10.0", "12.9", true}, // numeric, not lexical
		{"2.6.0", "2.6", false},
		{"", "1.54", false},
		{"1.55.0", "", false},
		{"unsupported output format: raw", "1.54", false},
	}
	for _, c := range cases {
		if got := NewerThanTested(c.installed, c.tested); got != c.want {
			t.Errorf("NewerThanTested(%q, %q) = %v, want %v", c.installed, c.tested, got, c.want)
		}
	}
}

func TestMajorMinor(t *testing.T) {
	for in, want := range map[string]string{
		"1.54.1": "1.54", "v0.76.0": "0.76", "12.8.5": "12.8", "2.6": "2.6", "garbage": "", "": "",
	} {
		if got := MajorMinor(in); got != want {
			t.Errorf("MajorMinor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	cases := map[string]string{
		// syft version -o text
		"Application:   syft\nVersion:       1.54.1\nBuildDate:     2026-10-06T14:36:33Z\n": "1.54.1",
		// cdxgen --version prints bold ANSI around the banner
		"\x1b[1mCycloneDX Generator 12.8.5\x1b[0m\nRuntime: Node.js, Version: 26.5.0\n": "12.8.5",
		// trivy --version
		"Version: 0.75.0\nVulnerability DB:\n  Version: 2\n": "0.75.0",
		// osv-scanner --version
		"osv-scanner version: 2.6.0\nosv-scalibr version: 0.5.2\n": "2.6.0",
		// pre-release suffix is kept
		"syft 1.55.0-rc1\n": "1.55.0-rc1",
		// no version at all: first line, ANSI stripped, so the failure is readable
		"\x1b[31munsupported output format: raw\x1b[0m\nUsage: ...\n": "unsupported output format: raw",
	}
	for in, want := range cases {
		if got := parseVersion(in); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultAdaptersDeclareTestedThrough(t *testing.T) {
	for _, a := range Default() {
		if MajorMinor(a.TestedThrough) != a.TestedThrough {
			t.Errorf("%s: TestedThrough %q must be a bare major.minor", a.Name, a.TestedThrough)
		}
	}
}
