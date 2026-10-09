// Package report renders a scan result as Markdown (for PR comments / CI logs).
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

// Markdown renders the result.
func Markdown(res *model.Result, maxRows int) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	w("## sbomcmp — %s\n\n", res.Target)
	if res.Recommendation.Primary == "" {
		w("**No usable SBOM.** %s\n\n", strings.Join(res.Recommendation.Reasons, " "))
	} else {
		w("**Recommendation: `%s`**", res.Recommendation.Primary)
		if res.Recommendation.Secondary != "" {
			w(" (pair with `%s`)", res.Recommendation.Secondary)
		}
		w("\n\n")
		for _, r := range res.Recommendation.Reasons {
			w("- %s\n", r)
		}
	}
	for _, c := range res.Recommendation.Caveats {
		w("- ⚠️ %s\n", c)
	}
	w("\n%s\n", ActNow(res))

	w("| Tool | Version | Components | Coverage | Unique | Unique+Vuln | Crit/High | Ecosystems only here | Time |\n")
	w("|---|---|---:|---:|---:|---:|---:|---|---:|\n")
	for _, s := range res.Summaries {
		var g model.GeneratorRun
		for _, gg := range res.Generators {
			if gg.Name == s.Name {
				g = gg
			}
		}
		w("| %s | %s | %d | %.0f%% | %d | %d | %d | %s | %dms |\n",
			s.Name, g.Version, s.Total, s.Coverage*100, s.Unique, s.UniqueVuln, s.UniqueCritHigh,
			strings.Join(s.TypesOnly, ", "), g.DurationMS)
	}
	for _, g := range res.Generators {
		if !g.Available || g.Error != "" {
			w("| %s | — | — | — | — | — | — | _%s_ | — |\n", g.Name, cell(g.Error))
		}
	}
	for _, g := range res.Generators {
		if g.Note != "" {
			w("\n- ⚠️ %s: %s", g.Name, cell(g.Note))
		}
	}
	w("\nUnion **%d** · all tools agree on **%d**\n\n", res.Union, res.Intersection)
	w("%s\n\n", VulnStatus(res))

	if len(res.Pairs) > 0 {
		w("### Pairwise\n\n| A | B | both | only A | only B | Jaccard | version disagreements |\n|---|---|---:|---:|---:|---:|---:|\n")
		for _, p := range res.Pairs {
			w("| %s | %s | %d | %d | %d | %.2f | %d |\n", p.A, p.B, p.Both, len(p.OnlyA), len(p.OnlyB), p.Jaccard, len(p.VersionDisagree))
		}
		w("\n")
	}

	// Decision-driving rows: not seen by all AND vulnerable or flagged, sorted by severity.
	var hot []model.Row
	for _, r := range res.Rows {
		if r.Agreement != "all" && (len(r.Vulns) > 0 || len(r.Signals) > 0) {
			hot = append(hot, r)
		}
	}
	// With VDB data, exploited-in-the-wild (KEV) and likely-to-be-exploited
	// (EPSS) advisories outrank raw severity.
	var epss bool
	for _, r := range hot {
		if r.MaxEPSS() > 0 {
			epss = true
			break
		}
	}
	sort.SliceStable(hot, func(i, j int) bool {
		a, b := hot[i], hot[j]
		if epss {
			if a.HasKEV() != b.HasKEV() {
				return a.HasKEV()
			}
			if ea, eb := a.MaxEPSS(), b.MaxEPSS(); ea != eb {
				return ea > eb
			}
		}
		return model.SeverityRank[a.MaxSev] > model.SeverityRank[b.MaxSev]
	})
	if len(hot) > 0 {
		w("### Disagreements that matter\n\n")
		if epss {
			w("| Component | Found by | Severity | EPSS | Vulns / signals | Why tools disagree |\n|---|---|---|---:|---|---|\n")
		} else {
			w("| Component | Found by | Severity | Vulns / signals | Why tools disagree |\n|---|---|---|---|---|\n")
		}
		for i, r := range hot {
			if i >= maxRows {
				if epss {
					w("| … | | | | | %d more |\n", len(hot)-maxRows)
				} else {
					w("| … | | | | %d more |\n", len(hot)-maxRows)
				}
				break
			}
			var ids []string
			for _, v := range r.Vulns {
				id := v.ID
				if v.Malicious {
					id += " (MALICIOUS)"
				}
				if v.KEV {
					id += " (KEV)"
				}
				ids = append(ids, id)
			}
			if r.VulnTotal > len(r.Vulns) {
				ids = append(ids, fmt.Sprintf("+%d more", r.VulnTotal-len(r.Vulns)))
			}
			for _, s := range r.Signals {
				ids = append(ids, fmt.Sprintf("%s:%s", s.Kind, s.Level))
			}
			if epss {
				e := "—"
				if v := r.MaxEPSS(); v > 0 {
					e = fmt.Sprintf("%.1f%%", v*100)
				}
				w("| `%s` | %s | %s | %s | %s | %s |\n", r.Key+installedMark(r), strings.Join(r.FoundBy, ", "), r.MaxSev, e,
					strings.Join(ids, "<br>"), cell(strings.Join(r.Reasons, "<br>")))
			} else {
				w("| `%s` | %s | %s | %s | %s |\n", r.Key+installedMark(r), strings.Join(r.FoundBy, ", "), r.MaxSev,
					strings.Join(ids, "<br>"), cell(strings.Join(r.Reasons, "<br>")))
			}
		}
		w("\n")
	}

	if len(res.MCP) > 0 {
		w("### Shared blind spot: MCP servers (not in any SBOM)\n\n| Server | Source | Command / URL | Registry | Signals |\n|---|---|---|---|---|\n")
		for _, m := range res.MCP {
			cu := m.Command
			if len(m.Args) > 0 {
				cu += " " + strings.Join(m.Args, " ")
			}
			if m.URL != "" {
				cu = m.URL
			}
			reg := "—"
			if m.Registry != nil {
				reg = m.Registry.TrustTier
				if len(m.Registry.Scopes) > 0 {
					reg += " · " + strings.Join(m.Registry.Scopes, " ")
				}
				if m.Registry.ScopeDrift != "" {
					reg += " · drift " + m.Registry.ScopeDrift
				}
			}
			var sig []string
			for _, s := range m.Signals {
				sig = append(sig, s.Message)
			}
			w("| %s | %s | `%s` | %s | %s |\n", m.Name, m.Source, cell(cu), cell(reg), cell(strings.Join(sig, "<br>")))
		}
		w("\n")
	}
	return b.String()
}

// NeedVDBLine is shown in place of the action list when the scan ran
// without VDB-only data.
const NeedVDBLine = "Exploitation (KEV/EPSS), malicious-release, registry and MCP signals need VDB — set `VDB_API_KEY` or run with `--vuln-source vdb`."

// NoActionsLine is shown when VDB answered and found nothing to act on.
const NoActionsLine = "No VDB-only findings: nothing being exploited, no malicious releases, no unknown names, no unverified MCP servers."

// ActNow renders the action list as a Markdown block: a table of what to
// remove, upgrade, check or review, or one line saying why there is none.
func ActNow(res *model.Result) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	if !res.VDBSignalsActive() {
		w("_%s_\n", NeedVDBLine)
		return b.String()
	}
	if len(res.Actions) == 0 {
		w("**Act now:** %s\n", NoActionsLine)
		return b.String()
	}
	w("**Act now** (%d)\n\n| | Component | Why | Fix |\n|---|---|---|---|\n", res.ActionTotal)
	for _, a := range res.Actions {
		mark := "⚠️ warn"
		if a.Level == "refuse" {
			mark = "🛑 refuse"
		}
		key := "`" + a.Key + "`"
		if a.Kind == "mcp" {
			key = "MCP `" + a.Key + "`"
		}
		w("| %s | %s | %s | **%s** |\n", mark, cell(key), cell(a.Message), cell(a.Fix))
	}
	if res.ActionTotal > len(res.Actions) {
		w("| … | | %d more | |\n", res.ActionTotal-len(res.Actions))
	}
	return b.String()
}

// ActionLines renders actions as plain text, one per line, for terminals.
func ActionLines(actions []model.Action) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		key := a.Key
		if a.Kind == "mcp" {
			key = "MCP " + a.Key
		}
		out = append(out, fmt.Sprintf("[%s] %s — %s → %s", a.Level, key, a.Message, a.Fix))
	}
	return out
}

// installedMark tags rows seen only inside installed trees.
func installedMark(r model.Row) string {
	if r.Installed {
		return "` (installed tree) `"
	}
	return ""
}

// cell escapes pipes so free text cannot break a Markdown table.
func cell(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// VulnStatus is the one-line coverage summary of the vulnerability source:
// which source, keyed or anonymous, how many queries were answered, what VDB
// added, and the fix when coverage is incomplete. The viewer renders the same
// line as its status strip.
func VulnStatus(res *model.Result) string {
	v := res.Vuln
	var b strings.Builder
	b.WriteString("Vulnerability data: ")
	switch {
	case v.Source == "none" || v.Source == "":
		b.WriteString("none (disabled) — scores reflect coverage only.")
		return b.String()
	case !v.Enabled:
		fmt.Fprintf(&b, "%s — not applied", v.Source)
		if v.Error != "" {
			fmt.Fprintf(&b, " (_%s_)", cell(v.Error))
		}
		b.WriteString(" — scores reflect coverage only.")
		return b.String()
	}
	b.WriteString(v.Source)
	if v.Source == "vdb" {
		if v.Anonymous {
			b.WriteString(" (anonymous)")
		} else {
			b.WriteString(" (keyed)")
		}
	}
	short := v.Answered < v.Queried
	if short {
		fmt.Fprintf(&b, " · ⚠️ answered **%d of %d**", v.Answered, v.Queried)
	} else {
		fmt.Fprintf(&b, " · answered %d of %d", v.Answered, v.Queried)
	}
	if v.FirstParty > 0 {
		fmt.Fprintf(&b, " · %d first-party (not checked)", v.FirstParty)
	}
	if v.DetailsCapped > 0 {
		fmt.Fprintf(&b, " · %d advisories unscored (OSV detail cap), shown as UNKNOWN", v.DetailsCapped)
	}
	if v.Source == "vdb" || v.VDBExtras {
		a := model.SummarizeVDB(res)
		if !a.Any() {
			b.WriteString(" · no VDB-only signals in this project")
		} else {
			var parts []string
			if a.KEVRows > 0 {
				parts = append(parts, fmt.Sprintf("%d KEV %s", a.KEVRows, plural(a.KEVRows, "row")))
			}
			if a.EPSSRows > 0 {
				parts = append(parts, fmt.Sprintf("%d %s with EPSS ≥ %.0f%%", a.EPSSRows, plural(a.EPSSRows, "row"), model.EPSSNotable*100))
			}
			if a.SlopRows > 0 {
				parts = append(parts, fmt.Sprintf("%d slopsquat %s", a.SlopRows, plural(a.SlopRows, "signal")))
			}
			if a.MCPRegistry > 0 {
				parts = append(parts, fmt.Sprintf("%d MCP registry %s", a.MCPRegistry, plural(a.MCPRegistry, "hit")))
			}
			b.WriteString(" · VDB added: " + strings.Join(parts, ", "))
		}
	}
	if short {
		if v.Source == "vdb" && v.Anonymous {
			b.WriteString(" — anonymous quota; `export VDB_API_KEY=…` (free at vdb.ai.kr/signup) for full coverage")
		} else if v.Error != "" {
			fmt.Fprintf(&b, " — _%s_", cell(v.Error))
		}
	} else if v.Error != "" {
		fmt.Fprintf(&b, " (_%s_)", cell(v.Error))
	}
	return b.String()
}

func plural(n int, s string) string {
	if n == 1 {
		return s
	}
	return s + "s"
}
