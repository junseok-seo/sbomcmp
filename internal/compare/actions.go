package compare

import (
	"fmt"
	"sort"
	"strings"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

// DangerousScopes are MCP registry scopes that let a server act beyond the
// conversation: run commands, write files, reach the network, read secrets.
var DangerousScopes = []string{"exec", "fs:write", "net:outbound", "secret:read"}

// HallucinatedNameReason is appended to a row's Reasons when a registry says
// the name does not exist; %s is the purl type.
const HallucinatedNameReason = "hallucinated-name: not on the %s registry (VDB); tools differ on unresolvable dependencies"

// explainSignals adds signal-derived reasons to rows: a slopsquat signal is
// itself an explanation of why tools disagree (one tool copied a name out of
// the manifest that no registry can resolve). Idempotent.
func explainSignals(rows []model.Row) {
	for i := range rows {
		r := &rows[i]
		if r.FirstParty || !hasSignal(r.Signals, "slopsquat") {
			continue
		}
		reason := fmt.Sprintf(HallucinatedNameReason, r.Type)
		dup := false
		for _, x := range r.Reasons {
			if x == reason {
				dup = true
				break
			}
		}
		if !dup {
			r.Reasons = append(r.Reasons, reason)
		}
	}
}

func hasSignal(sigs []model.Signal, kind string) bool {
	for _, s := range sigs {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

func signalLevel(sigs []model.Signal, kind string) string {
	best := ""
	for _, s := range sigs {
		if s.Kind == kind && model.ActionLevelRank[s.Level] > model.ActionLevelRank[best] {
			best = s.Level
		}
	}
	return best
}

func firstSignalMessage(sigs []model.Signal, kind string) string {
	for _, s := range sigs {
		if s.Kind == kind {
			return s.Message
		}
	}
	return ""
}

// actions turns the VDB-only findings on rows and MCP servers into an
// ordered to-do list: malicious releases, then CISA KEV, then EPSS at or
// above model.EPSSNotable, then slopsquat names, then MCP servers that are
// unverified/community with a dangerous scope or a refuse-level signal. A
// row contributes at most one action (its most urgent one). The list is
// capped at model.MaxActions; the second return value is the uncapped count.
func actions(rows []model.Row, servers []model.MCPServer) ([]model.Action, int) {
	var mal, kev, epss, slop, mcp []model.Action
	for _, r := range rows {
		if r.Installed {
			// Seen only inside node_modules / .venv / …: what is on this
			// machine, not what the code declares. Stays in the matrix.
			continue
		}
		switch {
		case r.HasMalicious():
			v := pickVuln(r.Vulns, func(v model.Vuln) bool { return v.Malicious })
			mal = append(mal, model.Action{Kind: "malicious", Level: "refuse", Key: r.Key,
				Message: v.ID + ": this version is a known malicious release", Fix: "remove"})
		case r.HasKEV():
			v := pickVuln(r.Vulns, func(v model.Vuln) bool { return v.KEV })
			kev = append(kev, model.Action{Kind: "kev", Level: "refuse", Key: r.Key,
				Message: v.ID + ": in CISA KEV (exploited in the wild)" + epssSuffix(v), Fix: upgradeFix(v)})
		case r.MaxEPSS() >= model.EPSSNotable:
			v := pickVuln(r.Vulns, func(v model.Vuln) bool { return v.EPSS >= model.EPSSNotable })
			epss = append(epss, model.Action{Kind: "epss", Level: "warn", Key: r.Key,
				Message: fmt.Sprintf("%s: EPSS %.0f%% (likely to be exploited within 30 days)", v.ID, v.EPSS*100), Fix: upgradeFix(v)})
		case !r.FirstParty && hasSignal(r.Signals, "slopsquat"):
			level := signalLevel(r.Signals, "slopsquat")
			if level != "refuse" {
				level = "warn"
			}
			msg := "name not found on the " + r.Type + " registry (possible slopsquatting)"
			if m := firstSignalMessage(r.Signals, "slopsquat"); m != "" {
				msg = m
			}
			slop = append(slop, model.Action{Kind: "slopsquat", Level: level, Key: r.Key, Message: msg, Fix: "check the name"})
		}
	}
	// Highest EPSS first within the group; the other groups keep row order.
	sort.SliceStable(epss, func(i, j int) bool { return epssOf(rows, epss[i].Key) > epssOf(rows, epss[j].Key) })

	for _, m := range servers {
		refuse := false
		for _, s := range m.Signals {
			if s.Level == "refuse" {
				refuse = true
				break
			}
		}
		tier := ""
		var danger []string
		if m.Registry != nil {
			tier = m.Registry.TrustTier
			for _, sc := range m.Registry.Scopes {
				for _, d := range DangerousScopes {
					if sc == d {
						danger = append(danger, sc)
					}
				}
			}
		}
		untrusted := tier == "unverified" || tier == "community"
		if !refuse && !(untrusted && len(danger) > 0) {
			continue
		}
		level := "warn"
		if refuse {
			level = "refuse"
		}
		var parts []string
		if tier != "" {
			parts = append(parts, "trust "+tier)
		}
		if len(danger) > 0 {
			parts = append(parts, "scopes "+strings.Join(danger, " "))
		}
		if m.Registry != nil && m.Registry.ScopeDrift != "" {
			parts = append(parts, "scope drift "+m.Registry.ScopeDrift)
		}
		if refuse {
			if msg := refuseMessage(m.Signals); msg != "" {
				parts = append(parts, msg)
			}
		}
		mcp = append(mcp, model.Action{Kind: "mcp", Level: level, Key: m.Name,
			Message: "MCP server " + strings.Join(parts, ", "), Fix: "pin and review the server"})
	}

	all := append(append(append(append(mal, kev...), epss...), slop...), mcp...)
	total := len(all)
	if total > model.MaxActions {
		all = all[:model.MaxActions]
	}
	return all, total
}

func pickVuln(vs []model.Vuln, ok func(model.Vuln) bool) model.Vuln {
	best := model.Vuln{}
	found := false
	for _, v := range vs {
		if !ok(v) {
			continue
		}
		// Prefer the one with a known fix, then the highest EPSS.
		if !found || (best.Fixed == "" && v.Fixed != "") || (v.Fixed != "" && v.EPSS > best.EPSS) {
			best, found = v, true
		}
	}
	return best
}

func epssOf(rows []model.Row, key string) float64 {
	for _, r := range rows {
		if r.Key == key {
			return r.MaxEPSS()
		}
	}
	return 0
}

func epssSuffix(v model.Vuln) string {
	if v.EPSS > 0 {
		return fmt.Sprintf(", EPSS %.0f%%", v.EPSS*100)
	}
	return ""
}

func upgradeFix(v model.Vuln) string {
	if v.Fixed != "" {
		return "upgrade to " + v.Fixed
	}
	return "upgrade (no fixed version published yet)"
}

func refuseMessage(sigs []model.Signal) string {
	for _, s := range sigs {
		if s.Level == "refuse" {
			return s.Message
		}
	}
	return ""
}
