// sbomcmp runs every available SBOM generator against one target, normalizes
// the results onto purl keys, explains where the tools disagree, weights the
// disagreements by vulnerability data, and recommends a primary tool.
//
//	sbomcmp scan ./repo                 # run all generators, write sbomcmp.json
//	sbomcmp scan image:nginx:1.27       # container image
//	sbomcmp ui                          # open the viewer on localhost
//	sbomcmp report --format md          # Markdown for PR comments
//	sbomcmp report --fail-on warn       # CI gate: exit 3 on VDB-only findings
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/compare"
	"github.com/junseok-seo/sbomcmp/internal/firstparty"
	"github.com/junseok-seo/sbomcmp/internal/gen"
	"github.com/junseok-seo/sbomcmp/internal/mcp"
	"github.com/junseok-seo/sbomcmp/internal/model"
	"github.com/junseok-seo/sbomcmp/internal/osv"
	"github.com/junseok-seo/sbomcmp/internal/report"
	"github.com/junseok-seo/sbomcmp/internal/ui"
	"github.com/junseok-seo/sbomcmp/internal/vuln"
)

// version is set at build time: -ldflags "-X main.version=v0.2.0". Binaries
// built by "go install …@vX.Y.Z" get the module version from build info.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "ui":
		err = cmdUI(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "push":
		err = cmdPush(os.Args[2:])
	case "generators":
		for _, a := range gen.Default() {
			fmt.Printf("%-12s %s\n", a.Name, a.Notes)
		}
	case "version", "--version", "-v":
		fmt.Println("sbomcmp", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		var ec exitError
		if errors.As(err, &ec) {
			os.Exit(int(ec))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// exitError carries a non-error exit status (the --fail-on gate).
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

// ExitFailOn is the status when --fail-on finds an action at or above the
// requested level: distinct from 1 (sbomcmp itself failed) and 2 (usage).
const ExitFailOn = 3

func checkFailOn(level string) error {
	switch level {
	case "none", "warn", "refuse":
		return nil
	}
	return fmt.Errorf("--fail-on must be none, warn or refuse")
}

// failOn prints the actions at or above level to stderr and returns the
// gate's exit status when there are any.
func failOn(res *model.Result, level string) error {
	acts := res.ActionsAtLeast(level)
	if len(acts) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "sbomcmp: %d action(s) at level %s or above (--fail-on %s):\n", len(acts), level, level)
	for _, l := range report.ActionLines(acts) {
		fmt.Fprintln(os.Stderr, "  "+l)
	}
	if res.ActionTotal > len(res.Actions) {
		fmt.Fprintf(os.Stderr, "  … %d more in the result file\n", res.ActionTotal-len(res.Actions))
	}
	return exitError(ExitFailOn)
}

func usage() {
	fmt.Fprintf(os.Stderr, `sbomcmp %s — run every SBOM generator, compare, explain, recommend

Usage:
  sbomcmp scan [flags] <dir | image:NAME>
  sbomcmp ui   [flags]
  sbomcmp report [flags]
  sbomcmp push [flags]            upload the recommended tool's SBOM to VDB (--watch: keep re-checking)
  sbomcmp generators

Run "sbomcmp <command> -h" for flags.

Environment:
  VDB_API_KEY       VDB bearer token; when set, vulnerability data comes from VDB
                    together with slopsquatting and MCP registry signals
  VDB_API_URL       VDB origin (default https://vdb.ai.kr)
  SBOMCMP_OSV_API   OSV-compatible base URL (default https://api.osv.dev)
`, version)
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	out := fs.String("o", "sbomcmp.json", "result file")
	rawDir := fs.String("raw-dir", "", "directory for raw per-tool SBOMs (default: <out>.raw/)")
	only := fs.String("only", "", "comma-separated generator names to run (default: all available)")
	extraBin := fs.String("bin", "", "extra PATH dirs (colon-separated), e.g. mock generators")
	timeout := fs.Duration("timeout", 10*time.Minute, "per-generator timeout")
	noVuln := fs.Bool("no-vuln", false, "skip vulnerability enrichment (same as --vuln-source none)")
	vulnSource := fs.String("vuln-source", "auto", "auto | osv | vdb | none (auto: vdb when VDB_API_KEY is set, else osv)")
	osvAPI := fs.String("osv-api", envOr("SBOMCMP_OSV_API", ""), "OSV-compatible base URL")
	vdbAPI := fs.String("vdb-api", envOr("VDB_API_URL", ""), "VDB origin")
	vulnKey := fs.String("vuln-key", os.Getenv("VDB_API_KEY"), "VDB bearer token (VDB_API_KEY)")
	vulnFixture := fs.String("vuln-fixture", "", "offline fixture JSON instead of any API")
	vulnAll := fs.Bool("vuln-all", false, "query every component, not only disagreements")
	vulnTimeout := fs.Duration("vuln-timeout", 60*time.Second, "HTTP timeout for vulnerability APIs")
	vulnDetails := fs.Int("vuln-details", osv.DefaultMaxDetails, "max distinct advisories to fetch OSV details for (0 = unlimited)")
	noMCP := fs.Bool("no-mcp", false, "skip MCP server discovery")
	openUI := fs.Bool("ui", false, "open the viewer after scanning")
	push, pushWatch := pushScanFlags(fs)
	failLevel := fs.String("fail-on", "none", "exit 3 when an action at this level or above exists: none | warn | refuse")
	quiet := fs.Bool("q", false, "quiet")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("scan needs exactly one target")
	}
	if *push || *pushWatch {
		requireKey(*vulnKey)
	}
	if err := checkFailOn(*failLevel); err != nil {
		return err
	}
	switch *vulnSource {
	case "auto", "osv", "vdb", "none":
	default:
		return fmt.Errorf("--vuln-source must be auto, osv, vdb or none")
	}
	if *noVuln {
		*vulnSource = "none"
	}
	target := fs.Arg(0)
	kind := "dir"
	if strings.HasPrefix(target, "image:") {
		kind = "image"
		target = strings.TrimPrefix(target, "image:")
	} else {
		abs, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		st, err := os.Stat(abs)
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return fmt.Errorf("%s is not a directory (use image:NAME for images)", target)
		}
		target = abs
	}
	if *rawDir == "" {
		*rawDir = strings.TrimSuffix(*out, filepath.Ext(*out)) + ".raw"
	}
	if err := os.MkdirAll(*rawDir, 0o755); err != nil {
		return err
	}
	log := func(s string) {
		if !*quiet {
			fmt.Fprintln(os.Stderr, s)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res := &model.Result{SchemaVersion: "1", Tool: "sbomcmp " + version, Target: target, TargetKind: kind, StartedAt: time.Now()}

	var onlyList []string
	if *only != "" {
		onlyList = strings.Split(*only, ",")
	}
	var bins []string
	if *extraBin != "" {
		bins = filepath.SplitList(*extraBin)
	}
	log(fmt.Sprintf("sbomcmp %s — scanning %s (%s)", version, target, kind))
	runs := gen.Run(ctx, gen.Default(), gen.Options{
		Target: target, Kind: kind, OutDir: *rawDir, Timeout: *timeout,
		Only: onlyList, ExtraBin: bins, Log: log,
	})
	res.Generators = runs

	res.Rows, res.Pairs = compare.Build(runs)
	log(fmt.Sprintf("union %d components across %d tools", len(res.Rows), countOK(runs)))

	// Packages the project declares itself are not registry dependencies:
	// keep them out of slopsquatting checks and say why in the viewer.
	var decls []firstparty.Decl
	if kind == "dir" {
		decls = firstparty.Collect(target)
	}
	for _, r := range runs {
		if d := firstparty.FromRoot(r.Name, r.Root); d != nil {
			decls = append(decls, *d)
		}
	}
	if n := firstparty.Mark(res.Rows, decls); n > 0 {
		log(fmt.Sprintf("%d component(s) are the project's own packages (not checked against registries)", n))
	}

	if kind == "dir" && !*noMCP {
		res.MCP = mcp.Discover(target)
		if len(res.MCP) > 0 {
			log(fmt.Sprintf("found %d MCP server reference(s) — not covered by any generator", len(res.MCP)))
		}
	}

	vcfg := vuln.Config{
		Source: *vulnSource, OSVEndpoint: *osvAPI, VDBEndpoint: *vdbAPI, VDBKey: *vulnKey,
		Fixture: *vulnFixture, Timeout: *vulnTimeout, OnlyDisagreements: !*vulnAll, OSVDetails: *vulnDetails, Log: log,
	}
	if vcfg.Resolve() == "none" {
		res.Vuln.Source = "none"
	} else {
		log(fmt.Sprintf("enriching with vulnerability data (%s)…", vcfg.Resolve()))
		vuln.Enrich(ctx, vcfg, res.Rows, &res.Vuln)
		if res.Vuln.Enabled {
			log(fmt.Sprintf("vuln: %s — %d queried, %d answered, %d with findings", res.Vuln.Source, res.Vuln.Queried, res.Vuln.Answered, res.Vuln.Hits))
			if res.Vuln.Note != "" {
				log("vuln: " + res.Vuln.Note)
			}
		}
		if len(res.MCP) > 0 {
			vuln.EnrichMCP(ctx, vcfg, res.MCP, &res.Vuln)
		}
	}

	compare.Finalize(res)
	res.FinishedAt = time.Now()

	// Per-run component lists are not serialized (rows carry everything).
	for i := range res.Generators {
		res.Generators[i].Components = nil
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}
	log("")
	log(summaryLine(res))
	log(fmt.Sprintf("wrote %s (raw SBOMs in %s/)", *out, *rawDir))

	if err := pushAfterScan(res, *push, *pushWatch, *vdbAPI, *vulnKey); err != nil {
		return err
	}
	if *openUI {
		if err := ui.Serve(res, *out, 0, true); err != nil {
			return err
		}
	}
	return failOn(res, *failLevel)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func countOK(runs []model.GeneratorRun) int {
	n := 0
	for _, r := range runs {
		if r.Available && r.Error == "" {
			n++
		}
	}
	return n
}

func summaryLine(res *model.Result) string {
	var b strings.Builder
	if res.Recommendation.Primary == "" {
		fmt.Fprintf(&b, "No recommendation: %s", strings.Join(res.Recommendation.Reasons, " "))
	} else {
		fmt.Fprintf(&b, "Recommendation: %s", res.Recommendation.Primary)
		if res.Recommendation.Secondary != "" {
			fmt.Fprintf(&b, " + %s", res.Recommendation.Secondary)
		}
		for _, r := range res.Recommendation.Reasons {
			fmt.Fprintf(&b, "\n  • %s", r)
		}
	}
	for _, c := range res.Recommendation.Caveats {
		fmt.Fprintf(&b, "\n  ⚠ %s", c)
	}
	switch {
	case !res.VDBSignalsActive():
		fmt.Fprintf(&b, "\nAct now: %s", strings.ReplaceAll(report.NeedVDBLine, "`", ""))
	case len(res.Actions) == 0:
		fmt.Fprintf(&b, "\nAct now: %s", report.NoActionsLine)
	default:
		fmt.Fprintf(&b, "\nAct now (%d):", res.ActionTotal)
		for _, l := range report.ActionLines(res.Actions) {
			fmt.Fprintf(&b, "\n  %s", l)
		}
		if res.ActionTotal > len(res.Actions) {
			fmt.Fprintf(&b, "\n  … %d more", res.ActionTotal-len(res.Actions))
		}
	}
	return b.String()
}

func loadResult(path string) (*model.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var res model.Result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func cmdUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	in := fs.String("i", "sbomcmp.json", "result file")
	port := fs.Int("port", 0, "port (0 = random free port)")
	noOpen := fs.Bool("no-open", false, "do not launch the browser")
	fs.Parse(args)
	res, err := loadResult(*in)
	if err != nil {
		return err
	}
	return ui.Serve(res, *in, *port, !*noOpen)
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	in := fs.String("i", "sbomcmp.json", "result file")
	format := fs.String("format", "md", "md | json")
	maxRows := fs.Int("max-rows", 40, "max disagreement rows in md")
	failLevel := fs.String("fail-on", "none", "exit 3 when an action at this level or above exists: none | warn | refuse")
	fs.Parse(args)
	if err := checkFailOn(*failLevel); err != nil {
		return err
	}
	res, err := loadResult(*in)
	if err != nil {
		return err
	}
	switch *format {
	case "md":
		fmt.Print(report.Markdown(res, *maxRows))
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	return failOn(res, *failLevel)
}
