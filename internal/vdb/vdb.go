// Package vdb is the adapter for VDB (https://vdb.ai.kr), an OSV-compatible
// vulnerability database that also carries signals CVE feeds do not:
// registry-missing names (slopsquatting), an MCP server registry with trust
// tiers and scopes, and AI model artifacts.
//
// sbomcmp uses one endpoint, POST /v1/ai/check-packages, which answers all of
// that for a batch of purls in a single round trip. Without an API key VDB
// still answers, but only 5 packages per request on a small hourly quota; a
// free key removes both limits.
package vdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

// DefaultEndpoint is the public VDB origin.
const DefaultEndpoint = "https://vdb.ai.kr"

// AnonymousBatch is the per-request cap VDB enforces without a key.
const AnonymousBatch = 5

// Client calls one VDB deployment.
type Client struct {
	Endpoint string
	APIKey   string
	HTTP     *http.Client
	// Batch is the number of purls per request (defaults: 100 with a key, 5 without).
	Batch int
}

// New returns a client with defaults applied.
func New(endpoint, apiKey string, timeout time.Duration) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	c := &Client{Endpoint: strings.TrimRight(endpoint, "/"), APIKey: apiKey, HTTP: &http.Client{Timeout: timeout}}
	if apiKey == "" {
		c.Batch = AnonymousBatch
	} else {
		c.Batch = 100
	}
	return c
}

// Result is one entry of check-packages' results[], aligned with the input.
type Result struct {
	Input       string    `json:"input"`
	Purl        string    `json:"purl"`
	Version     string    `json:"version"`
	Matched     bool      `json:"matched"`
	Risk        string    `json:"risk"` // high / medium / low / unknown / not_found
	AgentAction string    `json:"agent_action"`
	Because     string    `json:"because"`
	Reason      string    `json:"reason"`
	SafeUpgrade string    `json:"safe_upgrade"`
	Flags       []Flag    `json:"flags"`
	Registry    *Probe    `json:"registry"`
	MCP         *MCP      `json:"mcp"`
	Model       *Model    `json:"model"`
	Vulns       []VulnHit `json:"vulnerabilities"`
	VulnsTotal  int       `json:"vulnerabilities_total"`
	WorstBucket string    `json:"worst_bucket"` // worst severity across all advisories, including truncated ones
}

// Flag is a slopsquatting advisory attached to the exact purl.
type Flag struct {
	ID       string `json:"id"`
	SlopRisk string `json:"slop_risk"`
	Summary  string `json:"summary"`
}

// Probe is the live registry check.
type Probe struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Exists    *bool  `json:"exists"`
	Downloads *int64 `json:"downloads"`
	RiskHint  string `json:"risk_hint"` // not_found / high / medium / low / unknown
	Rationale string `json:"rationale"`
}

// MCP is a hit in VDB's MCP server registry.
type MCP struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	TrustTier   string   `json:"trust_tier"`
	Scopes      []string `json:"scopes"`
	RiskScore   *float64 `json:"risk_score"`
	RiskNotes   string   `json:"risk_notes"`
	ScopeDrift  *struct {
		Added     []string `json:"added"`
		Removed   []string `json:"removed"`
		ChangedAt string   `json:"changed_at"`
	} `json:"scope_drift"`
}

// Model is a hit in VDB's AI model artifact table.
type Model struct {
	ID        string   `json:"id"`
	Provider  string   `json:"provider"`
	License   string   `json:"license"`
	RiskScore *float64 `json:"risk_score"`
	RiskNotes string   `json:"risk_notes"`
}

// VulnHit is a version-filtered advisory for the package.
type VulnHit struct {
	ID             string   `json:"id"`
	Summary        string   `json:"summary"`
	SeverityBucket string   `json:"severity_bucket"`
	SeverityScore  float64  `json:"severity_score"`
	FixedIn        []string `json:"fixed_in"`
	KEV            bool     `json:"kev"`
	EPSS           *float64 `json:"epss"`
	Malicious      bool     `json:"malicious"`
}

// Quota is the anonymous-usage block VDB appends when no key was sent.
type Quota struct {
	Authenticated bool `json:"authenticated"`
	LimitPerHour  int  `json:"limit_per_hour"`
	Remaining     int  `json:"remaining"`
	ResetsIn      int  `json:"resets_in_seconds"`
}

type response struct {
	Results   []Result `json:"results"`
	Anonymous *Quota   `json:"anonymous"`
	Truncated *struct {
		Checked    int `json:"checked"`
		NotChecked int `json:"not_checked"`
	} `json:"truncated"`
}

// Check runs check-packages over purls in batches. The returned slice is
// aligned with the input; entries VDB did not answer (quota exhausted,
// truncated) are nil. The quota of the last response is returned when the
// call was anonymous.
func (c *Client) Check(ctx context.Context, purls []string) ([]*Result, *Quota, error) {
	out := make([]*Result, len(purls))
	var quota *Quota
	batch := c.Batch
	if batch <= 0 {
		batch = AnonymousBatch
	}
	for start := 0; start < len(purls); start += batch {
		if quota != nil && quota.Remaining == 0 {
			break
		}
		end := min(start+batch, len(purls))
		body, _ := json.Marshal(map[string]any{"packages": purls[start:end], "probe_registry": true})
		req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/v1/ai/check-packages", bytes.NewReader(body))
		if err != nil {
			return out, quota, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "sbomcmp")
		if c.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.APIKey)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return out, quota, fmt.Errorf("check-packages: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode == 401 {
			return out, quota, fmt.Errorf("check-packages: HTTP 401 — VDB_API_KEY was rejected")
		}
		if resp.StatusCode == 429 {
			return out, quota, fmt.Errorf("check-packages: HTTP 429 — anonymous quota exhausted; set VDB_API_KEY (free at %s/signup)", c.Endpoint)
		}
		if resp.StatusCode/100 != 2 {
			return out, quota, fmt.Errorf("check-packages: HTTP %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(data)), 200))
		}
		var r response
		if err := json.Unmarshal(data, &r); err != nil {
			return out, quota, fmt.Errorf("check-packages decode: %w", err)
		}
		if r.Anonymous != nil {
			quota = r.Anonymous
		}
		// Results are aligned with the request; VDB may answer fewer when it truncates.
		for k := range r.Results {
			if start+k < len(out) {
				rr := r.Results[k]
				out[start+k] = &rr
			}
		}
	}
	return out, quota, nil
}

// Apply writes a check-packages result onto a comparison row: advisories as
// Vulns, non-CVE findings as Signals.
func Apply(row *model.Row, r *Result) {
	if r == nil {
		return
	}
	for _, v := range r.Vulns {
		mv := model.Vuln{ID: v.ID, Summary: truncate(v.Summary, 160), Severity: bucket(v.SeverityBucket),
			Score: v.SeverityScore, KEV: v.KEV, Malicious: v.Malicious, Source: "vdb"}
		if len(v.FixedIn) > 0 {
			mv.Fixed = v.FixedIn[0]
		}
		if v.EPSS != nil {
			mv.EPSS = *v.EPSS
		}
		row.Vulns = append(row.Vulns, mv)
	}
	if r.VulnsTotal > len(r.Vulns) {
		row.VulnTotal = r.VulnsTotal
	}
	row.MaxSev = model.MaxSeverity(row.Vulns)
	// The list is truncated to the top few; worst_bucket covers the rest.
	if wb := bucket(r.WorstBucket); r.WorstBucket != "" && model.SeverityRank[wb] > model.SeverityRank[row.MaxSev] {
		row.MaxSev = wb
	}
	row.Signals = append(row.Signals, Signals(r)...)
}

// Signals converts the non-CVE parts of a result into sbomcmp signals.
func Signals(r *Result) []model.Signal {
	var out []model.Signal
	if r == nil {
		return nil
	}
	for _, v := range r.Vulns {
		if v.Malicious {
			out = append(out, model.Signal{Kind: "malicious", Level: "refuse", Source: "vdb",
				Message: v.ID + ": this package version is a known malicious release — remove it, do not upgrade around it"})
			break
		}
	}
	if r.Registry != nil && r.Registry.RiskHint == "not_found" {
		out = append(out, model.Signal{Kind: "slopsquat", Level: "refuse", Source: "vdb",
			Message: firstNonEmpty(r.Registry.Rationale, "name does not exist on the registry")})
	}
	for _, f := range r.Flags {
		level := "warn"
		if strings.EqualFold(f.SlopRisk, "high") {
			level = "refuse"
		}
		msg := f.ID
		if f.Summary != "" {
			msg += ": " + truncate(f.Summary, 140)
		}
		out = append(out, model.Signal{Kind: "slopsquat", Level: level, Source: "vdb", Message: msg})
	}
	if r.MCP != nil {
		out = append(out, mcpSignal(r.MCP))
	}
	if r.Model != nil {
		level := "info"
		if r.Model.RiskScore != nil && *r.Model.RiskScore >= 0.7 {
			level = "warn"
		}
		out = append(out, model.Signal{Kind: "model", Level: level, Source: "vdb",
			Message: firstNonEmpty(r.Model.RiskNotes, "known AI model artifact ("+r.Model.ID+")")})
	}
	return out
}

func mcpSignal(m *MCP) model.Signal {
	tier := strings.ToLower(m.TrustTier)
	level := "info"
	risk := 0.0
	if m.RiskScore != nil {
		risk = *m.RiskScore
	}
	switch {
	case (tier == "unverified" || tier == "community") && risk >= 0.7:
		level = "refuse"
	case tier == "unverified" || risk >= 0.4 || m.ScopeDrift != nil:
		level = "warn"
	}
	msg := fmt.Sprintf("in VDB MCP registry as %s, trust %s", m.ID, firstNonEmpty(tier, "unknown"))
	if len(m.Scopes) > 0 {
		msg += ", scopes " + strings.Join(m.Scopes, " ")
	}
	if m.ScopeDrift != nil {
		msg += " — scopes changed recently"
	}
	return model.Signal{Kind: "mcp", Level: level, Source: "vdb", Message: msg}
}

// Registry converts an MCP hit into the model's registry record.
func Registry(m *MCP) *model.MCPRegistry {
	if m == nil {
		return nil
	}
	reg := &model.MCPRegistry{ID: m.ID, DisplayName: m.DisplayName, TrustTier: strings.ToLower(m.TrustTier),
		Scopes: m.Scopes, RiskNotes: m.RiskNotes, Source: "vdb"}
	if m.RiskScore != nil {
		reg.RiskScore = *m.RiskScore
	}
	if d := m.ScopeDrift; d != nil {
		var parts []string
		if len(d.Added) > 0 {
			parts = append(parts, "+"+strings.Join(d.Added, " +"))
		}
		if len(d.Removed) > 0 {
			parts = append(parts, "-"+strings.Join(d.Removed, " -"))
		}
		reg.ScopeDrift = strings.Join(parts, " ")
		if d.ChangedAt != "" {
			reg.ScopeDrift += " (" + d.ChangedAt[:min(10, len(d.ChangedAt))] + ")"
		}
	}
	return reg
}

func bucket(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium", "moderate":
		return "MEDIUM"
	case "low":
		return "LOW"
	}
	return "UNKNOWN"
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
