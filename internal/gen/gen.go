// Package gen runs SBOM generators and collects their CycloneDX output.
//
// Each generator is an adapter that knows how to invoke one tool against a
// directory or a container image and ask for CycloneDX JSON. Adding a new
// tool means adding one Adapter.
package gen

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/cdx"
	"github.com/junseok-seo/sbomcmp/internal/model"
)

// Adapter describes how to drive one generator.
type Adapter struct {
	Name     string
	Binaries []string // candidate binary names, first found wins
	Version  func(bin string) string
	// Args builds the argv (after the binary) for a target. outPath is where the
	// tool should write; return writesStdout=true if the tool writes to stdout.
	Args func(target, kind, outPath string) (args []string, writesStdout bool)
	// Env adds environment variables.
	Env []string
	// Notes is shown in the Runs tab (what the tool needs to do well).
	Notes string
}

var versionRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.]+)?)`)

func versionFromCmd(bin string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if m := versionRe.FindStringSubmatch(string(out)); len(m) > 1 {
		return m[1]
	}
	return strings.TrimSpace(firstLine(string(out)))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Default returns the built-in adapters.
func Default() []Adapter {
	return []Adapter{
		{
			Name:     "syft",
			Binaries: []string{"syft"},
			Version:  func(bin string) string { return versionFromCmd(bin, "version", "-o", "raw") },
			Args: func(target, kind, out string) ([]string, bool) {
				src := target
				if kind == "dir" {
					src = "dir:" + target
				}
				return []string{"scan", src, "--scope", "all-layers", "-o", "cyclonedx-json=" + out, "-q"}, false
			},
			Env:   []string{"SYFT_CHECK_FOR_APP_UPDATE=false"},
			Notes: "reads manifests and lockfiles; strongest on container images and OS packages",
		},
		{
			Name:     "cdxgen",
			Binaries: []string{"cdxgen"},
			Version:  func(bin string) string { return versionFromCmd(bin, "--version") },
			Args: func(target, kind, out string) ([]string, bool) {
				if kind == "image" {
					return []string{"-t", "docker", "-o", out, target}, false
				}
				return []string{"-r", "-o", out, target}, false
			},
			Env:   []string{"CDXGEN_DEBUG_MODE=", "FETCH_LICENSE=false"},
			Notes: "resolves transitive dependencies when the build tooling is installed",
		},
		{
			Name:     "trivy",
			Binaries: []string{"trivy"},
			Version:  func(bin string) string { return versionFromCmd(bin, "--version") },
			Args: func(target, kind, out string) ([]string, bool) {
				sub := "fs"
				if kind == "image" {
					sub = "image"
				}
				return []string{sub, "--format", "cyclonedx", "--output", out, "--quiet", "--scanners", "", "--skip-db-update", "--offline-scan", target}, false
			},
			Env:   []string{"TRIVY_DISABLE_VEX_NOTICE=true"},
			Notes: "needs lockfiles for most language ecosystems (no package-lock.json → no npm)",
		},
		{
			Name:     "osv-scanner",
			Binaries: []string{"osv-scanner"},
			Version:  func(bin string) string { return versionFromCmd(bin, "--version") },
			Args: func(target, kind, out string) ([]string, bool) {
				// osv-scanner always scans for vulnerabilities while producing the SBOM;
				// sbomcmp reads only the component list from its output.
				if kind == "image" {
					return []string{"scan", "image", "--format", "cyclonedx-1-5", "--output", out, target}, false
				}
				return []string{"scan", "source", "-r", "--format", "cyclonedx-1-5", "--output", out, target}, false
			},
		},
	}
}

// Options control a scan.
type Options struct {
	Target   string
	Kind     string // dir | image
	OutDir   string // where raw SBOMs go
	Timeout  time.Duration
	Only     []string // restrict to these adapters
	ExtraBin []string // extra PATH dirs (e.g. mock generators)
	Log      func(string)
}

// Run executes all available adapters in parallel.
func Run(ctx context.Context, adapters []Adapter, opt Options) []model.GeneratorRun {
	if opt.Log == nil {
		opt.Log = func(string) {}
	}
	if opt.Timeout == 0 {
		opt.Timeout = 10 * time.Minute
	}
	path := os.Getenv("PATH")
	if len(opt.ExtraBin) > 0 {
		path = strings.Join(opt.ExtraBin, string(os.PathListSeparator)) + string(os.PathListSeparator) + path
	}
	only := map[string]bool{}
	for _, o := range opt.Only {
		only[strings.ToLower(o)] = true
	}

	runs := make([]model.GeneratorRun, len(adapters))
	var wg sync.WaitGroup
	for i, a := range adapters {
		if len(only) > 0 && !only[strings.ToLower(a.Name)] {
			continue
		}
		wg.Add(1)
		go func(i int, a Adapter) {
			defer wg.Done()
			runs[i] = runOne(ctx, a, opt, path)
		}(i, a)
	}
	wg.Wait()

	out := runs[:0]
	for _, r := range runs {
		if r.Name != "" {
			out = append(out, r)
		}
	}
	return out
}

func lookPath(bins []string, path string) string {
	for _, b := range bins {
		for _, dir := range filepath.SplitList(path) {
			p := filepath.Join(dir, b)
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				return p
			}
		}
	}
	return ""
}

func runOne(ctx context.Context, a Adapter, opt Options, path string) model.GeneratorRun {
	r := model.GeneratorRun{Name: a.Name, Types: map[string]int{}}
	bin := lookPath(a.Binaries, path)
	if bin == "" {
		r.Available = false
		r.Error = "binary not found in PATH"
		opt.Log(fmt.Sprintf("[%s] skipped: not installed", a.Name))
		return r
	}
	r.Available = true
	r.Binary = bin
	if a.Version != nil {
		r.Version = a.Version(bin)
	}

	outPath := filepath.Join(opt.OutDir, a.Name+".cdx.json")
	args, toStdout := a.Args(opt.Target, opt.Kind, outPath)
	r.Command = append([]string{bin}, args...)

	cctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = append(os.Environ(), "PATH="+path)
	cmd.Env = append(cmd.Env, a.Env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	opt.Log(fmt.Sprintf("[%s] running %s", a.Name, strings.Join(r.Command, " ")))
	start := time.Now()
	err := cmd.Run()
	r.Duration = time.Since(start)
	r.DurationMS = r.Duration.Milliseconds()
	if ee, ok := err.(*exec.ExitError); ok {
		r.ExitCode = ee.ExitCode()
	} else if err != nil {
		r.ExitCode = -1
	}

	var data []byte
	if toStdout {
		data = stdout.Bytes()
		_ = os.WriteFile(outPath, data, 0o644)
	} else {
		data, _ = os.ReadFile(outPath)
	}
	if len(data) == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "no output produced"
		}
		if err != nil {
			msg = err.Error() + ": " + msg
		}
		r.Error = truncate(msg, 400)
		opt.Log(fmt.Sprintf("[%s] failed: %s", a.Name, r.Error))
		return r
	}
	r.RawPath = outPath
	comps, format, skipped, perr := cdx.Parse(data)
	if perr != nil {
		r.Error = "parse: " + perr.Error()
		opt.Log(fmt.Sprintf("[%s] parse error: %v", a.Name, perr))
		return r
	}
	r.Components = comps
	r.Count = len(comps)
	r.Format = format
	r.Skipped = skipped
	for _, c := range comps {
		r.Types[c.Type]++
	}
	opt.Log(fmt.Sprintf("[%s] ok: %d components (%s) in %s", a.Name, r.Count, format, r.Duration.Round(time.Millisecond)))
	return r
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Names returns adapter names in order.
func Names(as []Adapter) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.Name)
	}
	sort.Strings(out)
	return out
}
