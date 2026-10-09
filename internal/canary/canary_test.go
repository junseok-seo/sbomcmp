//go:build canary

// Package canary holds the invariants the weekly upstream-drift workflow
// (.github/workflows/canary.yml) checks against results produced with the
// latest generator releases. It is excluded from the normal test run; build
// it with -tags canary and point it at result files:
//
//	CANARY_DIR_RESULT=dir.json CANARY_IMAGE_RESULT=image.json \
//	  go test -tags canary -count=1 -v ./internal/canary
//
// CANARY_REPORT, when set, receives a Markdown summary (versions, counts and
// every failed invariant) that the workflow puts in the job summary and in the
// drift issue.
package canary

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/junseok-seo/sbomcmp/internal/gen"
	"github.com/junseok-seo/sbomcmp/internal/model"
)

// Ecosystems each generator must still catalogue, per target kind. These are
// what the current releases produce for testdata/sample-project (manifests
// without lockfiles) and for a bare alpine image; a tool dropping one of them
// is the drift this canary exists to catch.
var required = map[string]map[string][]string{
	"dir": {
		"syft":        {"pypi", "golang"},
		"trivy":       {"pypi", "golang"},
		"cdxgen":      {"pypi", "golang"},
		"osv-scanner": {"pypi", "golang"},
	},
	"image": {
		"syft":        {"apk"},
		"trivy":       {"apk"},
		"cdxgen":      {"apk"},
		"osv-scanner": {"apk"},
	},
}

var versionLike = regexp.MustCompile(`^v?\d+\.\d+`)

type report struct {
	sections []string
	failures []string
}

func (r *report) failf(t *testing.T, g model.GeneratorRun, kind, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	t.Errorf("%s/%s: %s", kind, g.Name, msg)
	line := fmt.Sprintf("- **%s** (%s scan, version `%s`): %s", g.Name, kind, orDash(g.Version), msg)
	if g.Error != "" {
		line += fmt.Sprintf("\n  error: `%s`", strings.ReplaceAll(g.Error, "\n", " "))
	}
	r.failures = append(r.failures, line)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func TestInvariants(t *testing.T) {
	inputs := map[string]string{
		"dir":   os.Getenv("CANARY_DIR_RESULT"),
		"image": os.Getenv("CANARY_IMAGE_RESULT"),
	}
	if inputs["dir"] == "" && inputs["image"] == "" {
		t.Skip("set CANARY_DIR_RESULT and/or CANARY_IMAGE_RESULT")
	}
	rep := &report{}
	for _, kind := range []string{"dir", "image"} {
		path := inputs[kind]
		if path == "" {
			continue
		}
		t.Run(kind, func(t *testing.T) { checkResult(t, rep, kind, path) })
	}
	if out := os.Getenv("CANARY_REPORT"); out != "" {
		var b strings.Builder
		for _, s := range rep.sections {
			b.WriteString(s)
		}
		if len(rep.failures) > 0 {
			b.WriteString("### Failed invariants\n\n")
			b.WriteString(strings.Join(rep.failures, "\n"))
			b.WriteString("\n")
		} else {
			b.WriteString("All invariants held.\n")
		}
		if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}
}

func checkResult(t *testing.T, rep *report, kind, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var res model.Result
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if res.TargetKind != kind {
		t.Fatalf("%s: targetKind is %q", path, res.TargetKind)
	}

	byName := map[string]model.GeneratorRun{}
	for _, g := range res.Generators {
		byName[g.Name] = g
	}

	var sec strings.Builder
	fmt.Fprintf(&sec, "### %s scan — `%s`\n\n| Generator | Version | Format | Components | Ecosystems | Note |\n|---|---|---|---:|---|---|\n", kind, res.Target)
	names := gen.Names(gen.Default())
	for _, name := range names {
		g, ok := byName[name]
		if !ok {
			g = model.GeneratorRun{Name: name}
			rep.failf(t, g, kind, "missing from the result (adapter removed or filtered out)")
		}
		fmt.Fprintf(&sec, "| %s | %s | %s | %d | %s | %s |\n", g.Name, orDash(g.Version), orDash(g.Format), g.Count, typesOf(g), orDash(g.Note))
		if !ok {
			continue
		}
		if !g.Available {
			rep.failf(t, g, kind, "not available (install step broke, or the binary name changed)")
			continue
		}
		if g.Error != "" {
			rep.failf(t, g, kind, "run failed")
			continue
		}
		if !versionLike.MatchString(g.Version) {
			rep.failf(t, g, kind, "version probe did not return a version: %q", g.Version)
		}
		if !strings.HasPrefix(g.Format, "cyclonedx-") && g.Format != "spdx" {
			rep.failf(t, g, kind, "output format %q not recognized", g.Format)
		}
		if g.Count == 0 {
			rep.failf(t, g, kind, "zero comparable components")
		}
		for _, eco := range required[kind][g.Name] {
			if g.Types[eco] == 0 {
				rep.failf(t, g, kind, "no %s components (saw: %s)", eco, typesOf(g))
			}
		}
	}
	sec.WriteString("\n")
	rep.sections = append(rep.sections, sec.String())
}

func typesOf(g model.GeneratorRun) string {
	if len(g.Types) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(g.Types))
	for k := range g.Types {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, g.Types[k]))
	}
	return strings.Join(parts, ", ")
}
