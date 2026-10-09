package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/model"
	"github.com/junseok-seo/sbomcmp/internal/vdb"
)

// pushTop is how many findings the push summary lists.
const pushTop = 10

// errNoKey is printed verbatim; push exits 2 on it.
const errNoKey = "push needs VDB_API_KEY (free at https://vdb.ai.kr/signup)"

// pushOptions is everything push needs besides the result.
type pushOptions struct {
	Tool    string // generator whose raw SBOM is sent (default: the recommended primary)
	Watch   bool   // also register the SBOM as a watch
	VDBAPI  string // VDB origin ("" = default)
	Key     string // bearer token
	Timeout time.Duration
}

// cmdPush uploads the recommended tool's raw SBOM to VDB's one-shot scan
// and, with --watch, registers it for continuous re-checking.
func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	in := fs.String("i", "sbomcmp.json", "result file")
	tool := fs.String("tool", "", "generator whose SBOM to push (default: the recommended primary)")
	watch := fs.Bool("watch", false, "also register the SBOM as a VDB watch (re-checked as advisories arrive)")
	vdbAPI := fs.String("vdb-api", envOr("VDB_API_URL", ""), "VDB origin")
	key := fs.String("vuln-key", os.Getenv("VDB_API_KEY"), "VDB bearer token (VDB_API_KEY)")
	timeout := fs.Duration("timeout", 2*time.Minute, "HTTP timeout")
	fs.Parse(args)
	if fs.NArg() != 0 {
		return fmt.Errorf("push takes no positional arguments (use -i for the result file)")
	}
	opts := pushOptions{Tool: *tool, Watch: *watch, VDBAPI: *vdbAPI, Key: *key, Timeout: *timeout}
	requireKey(opts.Key)
	res, err := loadResult(*in)
	if err != nil {
		return err
	}
	return pushResult(res, opts)
}

// pushScanFlags registers scan's --push / --push-watch flags.
func pushScanFlags(fs *flag.FlagSet) (push, pushWatch *bool) {
	push = fs.Bool("push", false, "after writing the result, push the recommended tool's SBOM to VDB (needs VDB_API_KEY)")
	pushWatch = fs.Bool("push-watch", false, "like --push and also register the SBOM as a VDB watch")
	return push, pushWatch
}

// pushAfterScan is scan's hook: with --push or --push-watch it behaves
// exactly like running push on the written result.
func pushAfterScan(res *model.Result, push, pushWatch bool, vdbAPI, key string) error {
	if !push && !pushWatch {
		return nil
	}
	fmt.Fprintln(os.Stderr)
	return pushResult(res, pushOptions{Watch: pushWatch, VDBAPI: vdbAPI, Key: key, Timeout: 2 * time.Minute})
}

// requireKey exits 2 with the sign-up hint when no VDB key is configured.
// Scan calls it before running the generators so a missing key is not
// discovered ten minutes later.
func requireKey(key string) {
	if key == "" {
		fmt.Fprintln(os.Stderr, "error:", errNoKey)
		os.Exit(2)
	}
}

// pushResult does the work for both entry points.
func pushResult(res *model.Result, opts pushOptions) error {
	requireKey(opts.Key)
	tool, path, err := pickSBOM(res, opts.Tool)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s's raw SBOM is missing: %s (rerun sbomcmp scan; raw SBOMs live next to the result in <result>.raw/)", tool, path)
		}
		return err
	}
	filename := pushFilename(res.Target, tool)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := vdb.New(opts.VDBAPI, opts.Key, opts.Timeout)

	fmt.Fprintf(os.Stderr, "pushing %s (%s, %d components) to %s …\n", filename, tool, generatorCount(res, tool), client.Endpoint)
	scan, err := client.ScanSBOM(ctx, filename, data)
	if err != nil {
		return err
	}
	fmt.Print(pushSummary(scan, filename, client.Endpoint))

	if !opts.Watch {
		return nil
	}
	w, err := client.RegisterWatch(ctx, filename, data)
	if err != nil {
		var le *vdb.WatchLimitError
		if errors.As(err, &le) {
			fmt.Fprintln(os.Stderr, "error:", le.Error())
			os.Exit(1)
		}
		return err
	}
	name := w.Name
	if name == "" {
		name = w.Filename
	}
	fmt.Printf("Watch registered: id %s, name %s", w.ID, name)
	if w.ComponentCount > 0 {
		fmt.Printf(" (%d components)", w.ComponentCount)
	}
	fmt.Println(" — VDB re-checks it as advisories arrive and emails you.")
	return nil
}

// pickSBOM chooses the generator run whose raw SBOM is pushed.
func pickSBOM(res *model.Result, tool string) (string, string, error) {
	if tool == "" {
		tool = res.Recommendation.Primary
		if tool == "" {
			return "", "", fmt.Errorf("the result has no recommended tool (%s); choose one with --tool", strings.Join(res.Recommendation.Reasons, " "))
		}
	}
	var names []string
	for _, g := range res.Generators {
		if g.Name == tool {
			if g.RawPath == "" {
				return tool, "", fmt.Errorf("%s produced no SBOM in this result (%s)", tool, firstNonEmpty(g.Error, "not available"))
			}
			return tool, g.RawPath, nil
		}
		if g.RawPath != "" {
			names = append(names, g.Name)
		}
	}
	return tool, "", fmt.Errorf("no generator named %q in the result (have: %s)", tool, strings.Join(names, ", "))
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// pushFilename is <target-basename>-<tool>.cdx.json with anything a
// filesystem or a URL would choke on replaced.
func pushFilename(target, tool string) string {
	base := filepath.Base(strings.TrimRight(target, "/"))
	base = strings.Trim(unsafeName.ReplaceAllString(base, "-"), "-.")
	if base == "" {
		base = "sbom"
	}
	return base + "-" + tool + ".cdx.json"
}

func generatorCount(res *model.Result, tool string) int {
	for _, g := range res.Generators {
		if g.Name == tool {
			return g.Count
		}
	}
	return 0
}

// pushSummary renders the scan verdict for the terminal.
func pushSummary(s *vdb.ScanResult, filename, endpoint string) string {
	var b strings.Builder
	counts := s.Summary
	if counts.Empty() {
		counts = vdb.Counts{}
		for _, v := range s.Vulnerabilities {
			counts.Add(v.Bucket())
		}
	}
	fmt.Fprintf(&b, "VDB scan of %s: %d components", filename, s.ComponentsTotal)
	if bool(s.ComponentsTruncated) {
		b.WriteString(" (truncated: the server did not evaluate all of them)")
	}
	b.WriteString("\n")
	action := s.AgentAction
	if action == "" {
		action = "no verdict"
	}
	fmt.Fprintf(&b, "Verdict: %s — %s\n", action, severityLine(counts))

	vulns := append([]vdb.ScanVuln(nil), s.Vulnerabilities...)
	// Malicious releases first (remove, not upgrade), then exploited, then severity.
	sort.SliceStable(vulns, func(i, j int) bool {
		ri, rj := model.SeverityRank[vulns[i].Bucket()], model.SeverityRank[vulns[j].Bucket()]
		if vulns[i].Malicious != vulns[j].Malicious {
			return vulns[i].Malicious
		}
		if vulns[i].KEV != vulns[j].KEV {
			return vulns[i].KEV
		}
		if ri != rj {
			return ri > rj
		}
		return vulns[i].Score > vulns[j].Score
	})
	if len(vulns) > 0 {
		b.WriteString("Top findings:\n")
		w, ws := 0, 0
		for i, v := range vulns {
			if i == pushTop {
				break
			}
			w, ws = max(w, len(v.ID)), max(ws, len(v.Subject()))
		}
		for i, v := range vulns {
			if i == pushTop {
				fmt.Fprintf(&b, "  … and %d more\n", len(vulns)-pushTop)
				break
			}
			fixed := v.FixedVersion()
			if fixed == "" {
				fixed = "no fix"
			} else {
				fixed = "fixed " + fixed
			}
			extra := ""
			if v.KEV {
				extra = " KEV"
			}
			if v.Malicious {
				extra += " MALICIOUS"
			}
			fmt.Fprintf(&b, "  %-*s  %-8s  %-*s  %s%s\n", w, v.ID, v.Bucket(), ws, v.Subject(), fixed, extra)
		}
	}
	fmt.Fprintf(&b, "Full result: %s/sbom-scan\n", endpoint)
	return b.String()
}

func severityLine(c vdb.Counts) string {
	parts := []string{}
	for _, p := range []struct {
		n    int
		name string
	}{{c.Critical, "critical"}, {c.High, "high"}, {c.Medium, "medium"}, {c.Low, "low"}, {c.Unknown, "unknown"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.name))
		}
	}
	if len(parts) == 0 {
		if c.Total > 0 {
			return fmt.Sprintf("%d finding(s)", c.Total)
		}
		return "no known vulnerabilities"
	}
	return strings.Join(parts, ", ")
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
