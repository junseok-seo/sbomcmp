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
	w("\n")

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
	w("\nUnion **%d** · all tools agree on **%d** · vulnerability source: %s", res.Union, res.Intersection, res.Vuln.Source)
	if res.Vuln.Anonymous {
		w(" (anonymous)")
	}
	if res.Vuln.Error != "" {
		w(" (_%s_)", cell(res.Vuln.Error))
	}
	if res.Vuln.Note != "" {
		w(" (_%s_)", cell(res.Vuln.Note))
	}
	w("\n\n")

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
	sort.SliceStable(hot, func(i, j int) bool {
		return model.SeverityRank[hot[i].MaxSev] > model.SeverityRank[hot[j].MaxSev]
	})
	if len(hot) > 0 {
		w("### Disagreements that matter\n\n| Component | Found by | Severity | Vulns / signals | Why tools disagree |\n|---|---|---|---|---|\n")
		for i, r := range hot {
			if i >= maxRows {
				w("| … | | | | %d more |\n", len(hot)-maxRows)
				break
			}
			var ids []string
			for _, v := range r.Vulns {
				id := v.ID
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
			w("| `%s` | %s | %s | %s | %s |\n", r.Key, strings.Join(r.FoundBy, ", "), r.MaxSev,
				strings.Join(ids, "<br>"), cell(strings.Join(r.Reasons, "<br>")))
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

// cell escapes pipes so free text cannot break a Markdown table.
func cell(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
