// sbomcmp runs every available SBOM generator against one target, normalizes
// the results onto purl keys, explains where the tools disagree, weights the
// disagreements by vulnerability data, and recommends a primary tool.
//
//	sbomcmp scan ./repo                 # run all generators, write sbomcmp.json
//	sbomcmp scan image:nginx:1.27       # container image
//	sbomcmp ui                          # open the viewer on localhost
//	sbomcmp report --format md          # Markdown for PR comments
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/compare"
	"github.com/junseok-seo/sbomcmp/internal/gen"
	"github.com/junseok-seo/sbomcmp/internal/mcp"
	"github.com/junseok-seo/sbomcmp/internal/model"
	"github.com/junseok-seo/sbomcmp/internal/report"
	"github.com/junseok-seo/sbomcmp/internal/ui"
	"github.com/junseok-seo/sbomcmp/internal/vuln"
)

// version is set at build time: -ldflags "-X main.version=v0.2.0".
var version = "dev"

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
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `sbomcmp %s — run every SBOM generator, compare, explain, recommend

Usage:
  sbomcmp scan [flags] <dir | image:NAME>
  sbomcmp ui   [flags]
  sbomcmp report [flags]
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
	noMCP := fs.Bool("no-mcp", false, "skip MCP server discovery")
	openUI := fs.Bool("ui", false, "open the viewer after scanning")
	quiet := fs.Bool("q", false, "quiet")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("scan needs exactly one target")
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

	if kind == "dir" && !*noMCP {
		res.MCP = mcp.Discover(target)
		if len(res.MCP) > 0 {
			log(fmt.Sprintf("found %d MCP server reference(s) — not covered by any generator", len(res.MCP)))
		}
	}

	vcfg := vuln.Config{
		Source: *vulnSource, OSVEndpoint: *osvAPI, VDBEndpoint: *vdbAPI, VDBKey: *vulnKey,
		Fixture: *vulnFixture, Timeout: *vulnTimeout, OnlyDisagreements: !*vulnAll, Log: log,
	}
	if vcfg.Resolve() == "none" {
		res.Vuln.Source = "none"
	} else {
		log(fmt.Sprintf("enriching with vulnerability data (%s)…", vcfg.Resolve()))
		vuln.Enrich(ctx, vcfg, res.Rows, &res.Vuln)
		if res.Vuln.Enabled {
			log(fmt.Sprintf("vuln: %s — %d queried, %d with findings", res.Vuln.Source, res.Vuln.Queried, res.Vuln.Hits))
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

	if *openUI {
		return ui.Serve(res, *out, 0, true)
	}
	return nil
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
	fs.Parse(args)
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
		return enc.Encode(res)
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	return nil
}
