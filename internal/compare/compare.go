// Package compare builds the detection matrix, pairwise diffs, heuristic
// explanations for disagreements, and the final recommendation.
package compare

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

// Build computes rows and pairwise diffs from generator runs. Vulnerability and
// signal enrichment happens afterwards (see vuln package) and then Finalize
// computes summaries and the recommendation.
func Build(runs []model.GeneratorRun) ([]model.Row, []model.PairDiff) {
	rows := map[string]*model.Row{}
	// nameKey -> tool -> versions (for version-disagreement detection)
	nameVersions := map[string]map[string]map[string]bool{}
	toolTypes := map[string]map[string]bool{}

	var tools []string
	for _, r := range runs {
		if !r.Available || r.Error != "" {
			continue
		}
		tools = append(tools, r.Name)
		toolTypes[r.Name] = map[string]bool{}
		for _, c := range r.Components {
			toolTypes[r.Name][c.Type] = true
			row, ok := rows[c.Key]
			if !ok {
				row = &model.Row{
					Key: c.Key, NameKey: c.NameKey, Type: c.Type, Namespace: c.Namespace,
					Name: c.Name, Version: c.Version, Cells: map[string]model.Cell{}, FoundBy: []string{},
				}
				rows[c.Key] = row
			}
			row.Cells[r.Name] = model.Cell{Found: true, Version: c.Version, Purl: c.Purl, Scope: c.Scope}
			if nameVersions[c.NameKey] == nil {
				nameVersions[c.NameKey] = map[string]map[string]bool{}
			}
			if nameVersions[c.NameKey][r.Name] == nil {
				nameVersions[c.NameKey][r.Name] = map[string]bool{}
			}
			nameVersions[c.NameKey][r.Name][c.Version] = true
		}
	}
	sort.Strings(tools)

	out := make([]model.Row, 0, len(rows))
	for _, row := range rows {
		for _, t := range tools {
			if _, ok := row.Cells[t]; !ok {
				row.Cells[t] = model.Cell{Found: false}
			} else {
				row.FoundBy = append(row.FoundBy, t)
			}
		}
		sort.Strings(row.FoundBy)
		switch {
		case len(row.FoundBy) == len(tools):
			row.Agreement = "all"
		case len(row.FoundBy) == 1:
			row.Agreement = "single"
		default:
			row.Agreement = "partial"
		}
		if row.Agreement != "all" {
			row.Reasons = explain(row, tools, nameVersions, toolTypes)
		}
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Key < out[j].Key
	})

	// Pairwise diffs
	var pairs []model.PairDiff
	for i := 0; i < len(tools); i++ {
		for j := i + 1; j < len(tools); j++ {
			a, b := tools[i], tools[j]
			pd := model.PairDiff{A: a, B: b, OnlyA: []string{}, OnlyB: []string{}, VersionDisagree: []string{}}
			var both int
			seenNameA, seenNameB := map[string]map[string]bool{}, map[string]map[string]bool{}
			for _, r := range out {
				ca, cb := r.Cells[a].Found, r.Cells[b].Found
				switch {
				case ca && cb:
					both++
				case ca:
					pd.OnlyA = append(pd.OnlyA, r.Key)
				case cb:
					pd.OnlyB = append(pd.OnlyB, r.Key)
				}
				if ca {
					add(seenNameA, r.NameKey, r.Version)
				}
				if cb {
					add(seenNameB, r.NameKey, r.Version)
				}
			}
			pd.Both = both
			union := both + len(pd.OnlyA) + len(pd.OnlyB)
			if union > 0 {
				pd.Jaccard = round(float64(both) / float64(union))
			}
			for nk, va := range seenNameA {
				if vb, ok := seenNameB[nk]; ok && !sameSet(va, vb) {
					pd.VersionDisagree = append(pd.VersionDisagree, nk)
				}
			}
			sort.Strings(pd.VersionDisagree)
			pairs = append(pairs, pd)
		}
	}
	return out, pairs
}

func add(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func round(f float64) float64 { return math.Round(f*1000) / 1000 }

// explain produces human-readable reasons why a row is not seen by every tool.
func explain(row *model.Row, tools []string, nv map[string]map[string]map[string]bool, toolTypes map[string]map[string]bool) []string {
	var reasons []string
	seen := map[string]bool{}
	push := func(s string) {
		if !seen[s] {
			seen[s] = true
			reasons = append(reasons, s)
		}
	}
	for _, t := range tools {
		if row.Cells[t].Found {
			continue
		}
		// 1. Same package, different version in the missing tool.
		if vs, ok := nv[row.NameKey][t]; ok {
			var others []string
			for v := range vs {
				others = append(others, v)
			}
			sort.Strings(others)
			push(fmt.Sprintf("version-mismatch: %s reports %s as %s", t, row.NameKey, strings.Join(others, ", ")))
			continue
		}
		// 2. Missing tool never saw this ecosystem at all → cataloger coverage.
		if !toolTypes[t][row.Type] {
			push(fmt.Sprintf("ecosystem-coverage: %s detected no %s packages", t, row.Type))
			continue
		}
		// 3. Dev/optional scope — common cause of count differences.
		for _, ft := range row.FoundBy {
			if s := row.Cells[ft].Scope; s == "dev" || s == "optional" || s == "excluded" {
				push(fmt.Sprintf("scope: %s marks it %s; %s likely excludes that scope", ft, s, t))
				break
			}
		}
		if seen[fmt.Sprintf("scope: %s", t)] {
			continue
		}
		// 4. Type unknown → identifier format problem.
		if row.Type == "unknown" {
			push("purl-format: no purl emitted; matched by name only")
			continue
		}
		push(fmt.Sprintf("cataloger: %s saw %s packages but not this one (transitive depth, lockfile vs manifest, or vendored code)", t, row.Type))
	}
	return reasons
}

// Finalize computes per-tool summaries and the recommendation. Call after
// vulnerability enrichment so severity-weighted scores are available.
func Finalize(res *model.Result) {
	var tools []string
	for _, r := range res.Generators {
		if r.Available && r.Error == "" {
			tools = append(tools, r.Name)
		}
	}
	sort.Strings(tools)
	// Signal-derived reasons and the action list depend on enrichment, which
	// has already run by the time Finalize is called.
	explainSignals(res.Rows)
	res.Actions, res.ActionTotal = actions(res.Rows, res.MCP)
	res.Union = len(res.Rows)
	res.Intersection = 0
	for _, r := range res.Rows {
		if r.Agreement == "all" {
			res.Intersection++
		}
	}

	sums := map[string]*model.ToolSummary{}
	for _, t := range tools {
		sums[t] = &model.ToolSummary{Name: t, Types: map[string]int{}}
	}
	// Ecosystems seen per tool
	typeTools := map[string]map[string]bool{}
	for _, r := range res.Rows {
		for _, t := range r.FoundBy {
			s := sums[t]
			s.Total++
			s.Types[r.Type]++
			if typeTools[r.Type] == nil {
				typeTools[r.Type] = map[string]bool{}
			}
			typeTools[r.Type][t] = true
			if r.Agreement == "single" {
				s.Unique++
				if len(r.Vulns) > 0 {
					s.UniqueVuln++
					if r.MaxSev == "CRITICAL" || r.MaxSev == "HIGH" {
						s.UniqueCritHigh++
					}
				}
			}
		}
	}
	for typ, ts := range typeTools {
		if len(ts) == 1 {
			for t := range ts {
				sums[t].TypesOnly = append(sums[t].TypesOnly, typ)
			}
		}
	}

	// Score: coverage dominates, unique-vulnerable findings are a strong bonus,
	// unique ecosystems a small bonus. Scale 0–100.
	var best, second *model.ToolSummary
	for _, t := range tools {
		s := sums[t]
		if res.Union > 0 {
			s.Coverage = round(float64(s.Total) / float64(res.Union))
		}
		sort.Strings(s.TypesOnly)
		s.Score = round(60*s.Coverage +
			math.Min(25, float64(s.UniqueCritHigh)*8+float64(s.UniqueVuln-s.UniqueCritHigh)*3) +
			math.Min(15, float64(len(s.TypesOnly))*5))
		res.Summaries = append(res.Summaries, *s)
		if best == nil || s.Score > best.Score {
			second = best
			best = s
		} else if second == nil || s.Score > second.Score {
			second = s
		}
	}
	sort.Slice(res.Summaries, func(i, j int) bool { return res.Summaries[i].Score > res.Summaries[j].Score })

	rec := model.Recommendation{}
	if best == nil {
		rec.Reasons = []string{"No generator produced a usable SBOM. Install syft, cdxgen or trivy and re-run."}
		res.Recommendation = rec
		return
	}
	rec.Primary = best.Name
	rec.Reasons = append(rec.Reasons,
		fmt.Sprintf("%s covers %.0f%% of the union (%d of %d components).", best.Name, best.Coverage*100, best.Total, res.Union))
	if best.Unique > 0 {
		rec.Reasons = append(rec.Reasons, fmt.Sprintf("%d components were found only by %s.", best.Unique, best.Name))
	}
	if best.UniqueVuln > 0 {
		rec.Reasons = append(rec.Reasons, fmt.Sprintf("Of those, %d carry known vulnerabilities (%d critical/high) that the other tools would have missed.", best.UniqueVuln, best.UniqueCritHigh))
	}
	if len(best.TypesOnly) > 0 {
		rec.Reasons = append(rec.Reasons, fmt.Sprintf("Only %s catalogued: %s.", best.Name, strings.Join(best.TypesOnly, ", ")))
	}
	if second != nil && second.Total > 0 {
		// Does second add anything best lacks?
		var adds, addsVuln int
		for _, r := range res.Rows {
			if r.Cells[second.Name].Found && !r.Cells[best.Name].Found {
				adds++
				if len(r.Vulns) > 0 {
					addsVuln++
				}
			}
		}
		if adds > 0 {
			rec.Secondary = second.Name
			msg := fmt.Sprintf("Pair with %s: it adds %d components %s misses", second.Name, adds, best.Name)
			if addsVuln > 0 {
				msg += fmt.Sprintf(" (%d vulnerable)", addsVuln)
			}
			rec.Reasons = append(rec.Reasons, msg+".")
		}
	}
	if res.Intersection > 0 && res.Union > 0 {
		agree := float64(res.Intersection) / float64(res.Union)
		if agree < 0.6 {
			rec.Caveats = append(rec.Caveats, fmt.Sprintf("Tools agree on only %.0f%% of components. Differences are mostly explained by scope and ecosystem coverage — check the Reasons column before trusting any single count.", agree*100))
		}
	}
	for _, s := range res.Summaries {
		if s.Name != best.Name && s.UniqueCritHigh > 0 {
			rec.Caveats = append(rec.Caveats, fmt.Sprintf("%s alone finds %d critical/high vulnerable components. Dropping it has a security cost.", s.Name, s.UniqueCritHigh))
		}
	}
	rec.Caveats = append(rec.Caveats, vulnCaveats(res.Vuln)...)
	if len(res.MCP) > 0 {
		msg := fmt.Sprintf("%d MCP server(s) are configured in this project. No SBOM generator lists them — this is a shared blind spot.", len(res.MCP))
		var refuse, unverified int
		for _, m := range res.MCP {
			if m.Registry != nil && m.Registry.TrustTier == "unverified" {
				unverified++
			}
			for _, s := range m.Signals {
				if s.Level == "refuse" {
					refuse++
					break
				}
			}
		}
		if unverified > 0 {
			msg += fmt.Sprintf(" %d of them are not in the MCP registry (unverified publisher).", unverified)
		}
		if refuse > 0 {
			msg += fmt.Sprintf(" %d carry a refuse-level signal.", refuse)
		}
		rec.Caveats = append(rec.Caveats, msg)
	}
	var slop, malicious int
	for _, r := range res.Rows {
		if r.HasMalicious() {
			malicious++
		}
		for _, s := range r.Signals {
			if s.Kind == "slopsquat" {
				slop++
				break
			}
		}
	}
	if malicious > 0 {
		rec.Caveats = append(rec.Caveats, fmt.Sprintf("%d component version(s) are known malicious releases. Remove them before anything else; which tool found them is secondary.", malicious))
	}
	if slop > 0 {
		rec.Caveats = append(rec.Caveats, fmt.Sprintf("%d component name(s) do not exist on their registry (possible slopsquatting). Check the Signals filter before trusting the manifest.", slop))
	}
	res.Recommendation = rec
}

// vulnCaveats explains incomplete vulnerability enrichment: a source that
// answered only part of the queries (VDB's anonymous quota), advisories OSV
// left unscored because of the detail cap, or no enrichment at all.
func vulnCaveats(v model.VulnMeta) []string {
	var out []string
	if v.Enabled && v.Answered < v.Queried {
		why := "the source stopped answering"
		if v.Error != "" {
			why = v.Error
		}
		if v.Source == "vdb" && v.Anonymous {
			why = "VDB anonymous quota — set VDB_API_KEY for full coverage"
		}
		out = append(out, fmt.Sprintf("Vulnerability weighting covered only %d of %d disagreement rows (%s).", v.Answered, v.Queried, why))
	}
	if v.DetailsCapped > 0 {
		out = append(out, fmt.Sprintf("%d advisories were not scored (OSV detail cap); shown as UNKNOWN.", v.DetailsCapped))
	}
	if len(out) == 0 && !v.Enabled && v.Source != "none" {
		msg := "Vulnerability weighting was not applied (offline or disabled)."
		if v.Error != "" {
			msg = "Vulnerability weighting was not applied: " + v.Error + "."
		}
		out = append(out, msg+" Scores reflect coverage only.")
	} else if len(out) == 0 && v.Source == "none" {
		out = append(out, "Vulnerability weighting was not applied (disabled with --no-vuln). Scores reflect coverage only.")
	}
	return out
}
