// Package model defines the data types shared across sbomcmp.
package model

import "time"

// Component is one entry observed by one generator, after normalization.
type Component struct {
	Key       string            `json:"key"`     // normalized comparison key: type/namespace/name@version
	NameKey   string            `json:"nameKey"` // version-agnostic key: type/namespace/name
	Type      string            `json:"type"`    // purl type (npm, pypi, golang, deb, ...) or "unknown"
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Purl      string            `json:"purl,omitempty"`  // original purl as emitted
	Scope     string            `json:"scope,omitempty"` // required / optional / excluded / dev
	Licenses  []string          `json:"licenses,omitempty"`
	Props     map[string]string `json:"props,omitempty"` // selected tool-specific properties
}

// GeneratorRun is the record of one generator execution.
type GeneratorRun struct {
	Name       string         `json:"name"`
	Binary     string         `json:"binary"`
	Version    string         `json:"version"`
	Available  bool           `json:"available"`
	Command    []string       `json:"command,omitempty"`
	ExitCode   int            `json:"exitCode"`
	Duration   time.Duration  `json:"-"`
	DurationMS int64          `json:"durationMs"`
	Error      string         `json:"error,omitempty"`
	Note       string         `json:"note,omitempty"`    // non-fatal annotation (e.g. newer than the tested version)
	RawPath    string         `json:"rawPath,omitempty"` // where the raw CycloneDX was saved
	Format     string         `json:"format,omitempty"`  // cyclonedx-1.6 / spdx
	Count      int            `json:"count"`
	Skipped    int            `json:"skipped,omitempty"` // version-less entries not comparable
	Root       *Component     `json:"root,omitempty"`    // CycloneDX metadata.component (the scanned subject)
	Types      map[string]int `json:"types"`             // purl type -> count
	Components []Component    `json:"-"`                 // not serialized here; see Rows
}

// Cell is the per-tool observation of a component.
type Cell struct {
	Found   bool   `json:"found"`
	Version string `json:"version,omitempty"` // version this tool reported (may differ from row.Version)
	Purl    string `json:"purl,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// Row is one normalized component across all tools.
type Row struct {
	Key       string          `json:"key"`
	NameKey   string          `json:"nameKey"`
	Type      string          `json:"type"`
	Namespace string          `json:"namespace,omitempty"`
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Cells     map[string]Cell `json:"cells"` // tool name -> cell
	FoundBy   []string        `json:"foundBy"`
	Agreement string          `json:"agreement"`         // all / partial / single
	Reasons   []string        `json:"reasons,omitempty"` // why tools disagree (heuristic)
	Vulns     []Vuln          `json:"vulns,omitempty"`
	VulnTotal int             `json:"vulnTotal,omitempty"`   // > len(Vulns) when the source truncated the list
	MaxSev    string          `json:"maxSeverity,omitempty"` // CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
	Signals   []Signal        `json:"signals,omitempty"`     // non-CVE signals (slopsquat etc.)
	// FirstParty marks a package the project declares itself (its own
	// package.json, Cargo.toml, pyproject.toml, go.mod or a generator's
	// metadata.component). Not a registry dependency: never a slopsquat.
	FirstParty       bool   `json:"firstParty,omitempty"`
	FirstPartySource string `json:"firstPartySource,omitempty"`
}

// Vuln is a vulnerability hit from an OSV-compatible source.
type Vuln struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Severity  string   `json:"severity,omitempty"` // normalized bucket
	Score     float64  `json:"score,omitempty"`    // CVSS base score when known
	Fixed     string   `json:"fixed,omitempty"`
	KEV       bool     `json:"kev,omitempty"`       // CISA Known Exploited Vulnerabilities (VDB)
	EPSS      float64  `json:"epss,omitempty"`      // exploit probability 0–1 (VDB)
	Malicious bool     `json:"malicious,omitempty"` // malicious-package report (MAL-*), not a vulnerability
	Source    string   `json:"source"`              // osv / vdb / fixture
}

// Signal is a non-CVE risk signal (registry-missing name, MCP scope, etc.).
type Signal struct {
	Kind    string `json:"kind"`  // slopsquat / mcp / model / other
	Level   string `json:"level"` // refuse / warn / info
	Message string `json:"message"`
	Source  string `json:"source"` // local / vdb / fixture
}

// PairDiff is the difference between two tools.
type PairDiff struct {
	A               string   `json:"a"`
	B               string   `json:"b"`
	OnlyA           []string `json:"onlyA"` // row keys
	OnlyB           []string `json:"onlyB"`
	Both            int      `json:"both"`
	Jaccard         float64  `json:"jaccard"`
	VersionDisagree []string `json:"versionDisagree"` // nameKeys with different versions
}

// ToolSummary is per-tool roll-up used by the recommendation.
type ToolSummary struct {
	Name           string         `json:"name"`
	Total          int            `json:"total"`
	Unique         int            `json:"unique"`     // found only by this tool
	UniqueVuln     int            `json:"uniqueVuln"` // unique AND vulnerable
	UniqueCritHigh int            `json:"uniqueCritHigh"`
	Types          map[string]int `json:"types"`
	TypesOnly      []string       `json:"typesOnly"` // ecosystems only this tool saw
	Coverage       float64        `json:"coverage"`  // total / union
	Score          float64        `json:"score"`
}

// MCPServer is an MCP server reference discovered in config files (the "common blind spot").
type MCPServer struct {
	Name     string       `json:"name"`
	Source   string       `json:"source"` // config file path
	Command  string       `json:"command,omitempty"`
	URL      string       `json:"url,omitempty"`
	Args     []string     `json:"args,omitempty"`
	Package  string       `json:"package,omitempty"` // purl of the package the launcher runs (pkg:npm/…, pkg:pypi/…)
	Registry *MCPRegistry `json:"registry,omitempty"`
	Signals  []Signal     `json:"signals,omitempty"`
}

// MCPRegistry is what a registry (VDB) knows about an MCP server.
type MCPRegistry struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName,omitempty"`
	TrustTier   string   `json:"trustTier"` // official / partner / community / unverified
	Scopes      []string `json:"scopes,omitempty"`
	RiskScore   float64  `json:"riskScore,omitempty"`
	RiskNotes   string   `json:"riskNotes,omitempty"`
	ScopeDrift  string   `json:"scopeDrift,omitempty"` // human-readable summary of a recent scope change
	Source      string   `json:"source"`
}

// Result is the whole output of a scan.
type Result struct {
	SchemaVersion  string         `json:"schemaVersion"`
	Tool           string         `json:"tool"` // "sbomcmp <version>"
	Target         string         `json:"target"`
	TargetKind     string         `json:"targetKind"` // dir / image
	StartedAt      time.Time      `json:"startedAt"`
	FinishedAt     time.Time      `json:"finishedAt"`
	Generators     []GeneratorRun `json:"generators"`
	Rows           []Row          `json:"rows"`
	Union          int            `json:"union"`
	Intersection   int            `json:"intersection"`
	Pairs          []PairDiff     `json:"pairs"`
	Summaries      []ToolSummary  `json:"summaries"`
	Recommendation Recommendation `json:"recommendation"`
	Vuln           VulnMeta       `json:"vuln"`
	MCP            []MCPServer    `json:"mcpServers"`
	Notes          []string       `json:"notes,omitempty"`
}

// Recommendation is the final verdict with evidence.
type Recommendation struct {
	Primary   string   `json:"primary"`
	Secondary string   `json:"secondary,omitempty"`
	Reasons   []string `json:"reasons"`
	Caveats   []string `json:"caveats,omitempty"`
}

// VulnMeta records which vulnerability source was used.
type VulnMeta struct {
	Enabled    bool   `json:"enabled"`
	Source     string `json:"source"` // osv / vdb / fixture / none
	Endpoint   string `json:"endpoint,omitempty"`
	Queried    int    `json:"queried"`              // rows sent to the source
	Answered   int    `json:"answered"`             // rows the source actually answered (== Queried when complete)
	FirstParty int    `json:"firstParty,omitempty"` // rows skipped because the project declares them itself
	Hits       int    `json:"hits"`
	// DetailsCapped counts advisories left at UNKNOWN severity because the
	// OSV per-advisory detail fetch cap was hit (osv source only).
	DetailsCapped int    `json:"detailsCapped,omitempty"`
	Error         string `json:"error,omitempty"`
	Note          string `json:"note,omitempty"`
	VDBExtras     bool   `json:"vdbExtras"` // slopsquat / MCP registry signals active
	Anonymous     bool   `json:"anonymous,omitempty"`
}

// Complete reports whether every queried row got an answer.
func (m VulnMeta) Complete() bool { return m.Enabled && m.Answered >= m.Queried }

// SeverityRank orders severity buckets.
var SeverityRank = map[string]int{
	"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "": -1,
}

// MaxSeverity returns the highest bucket among vulns ("" when none).
func MaxSeverity(vs []Vuln) string {
	best := ""
	for _, v := range vs {
		if SeverityRank[v.Severity] > SeverityRank[best] {
			best = v.Severity
		}
	}
	if best == "" && len(vs) > 0 {
		return "UNKNOWN"
	}
	return best
}

// VDBAdditions counts what a VDB-backed scan adds beyond plain advisories:
// rows with a CISA KEV entry, rows whose top EPSS is at least EPSSNotable,
// rows with a slopsquat signal, and MCP servers found in the registry.
type VDBAdditions struct {
	KEVRows     int `json:"kevRows"`
	EPSSRows    int `json:"epssRows"`
	SlopRows    int `json:"slopRows"`
	MCPRegistry int `json:"mcpRegistry"`
}

// EPSSNotable is the exploit-probability threshold used for EPSSRows.
const EPSSNotable = 0.1

// Any reports whether at least one counter is non-zero.
func (a VDBAdditions) Any() bool {
	return a.KEVRows+a.EPSSRows+a.SlopRows+a.MCPRegistry > 0
}

// MaxEPSS returns the highest EPSS among a row's vulnerabilities (0 when none).
func (r Row) MaxEPSS() float64 {
	best := 0.0
	for _, v := range r.Vulns {
		if v.EPSS > best {
			best = v.EPSS
		}
	}
	return best
}

// HasKEV reports whether any of the row's vulnerabilities is in CISA KEV.
// HasMalicious reports whether any advisory on the row is a malicious-package report.
func (r Row) HasMalicious() bool {
	for _, v := range r.Vulns {
		if v.Malicious {
			return true
		}
	}
	return false
}

func (r Row) HasKEV() bool {
	for _, v := range r.Vulns {
		if v.KEV {
			return true
		}
	}
	return false
}

// SummarizeVDB computes VDBAdditions over a result.
func SummarizeVDB(res *Result) VDBAdditions {
	var a VDBAdditions
	for _, r := range res.Rows {
		if r.HasKEV() {
			a.KEVRows++
		}
		if r.MaxEPSS() >= EPSSNotable {
			a.EPSSRows++
		}
		for _, s := range r.Signals {
			if s.Kind == "slopsquat" {
				a.SlopRows++
				break
			}
		}
	}
	for _, m := range res.MCP {
		if m.Registry != nil && m.Registry.TrustTier != "unverified" {
			a.MCPRegistry++
		}
	}
	return a
}
