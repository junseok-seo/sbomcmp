// Package vuln enriches comparison rows (and discovered MCP servers) with
// vulnerability data. Three sources are supported:
//
//   - osv:     api.osv.dev or any OSV-compatible server (default, no key)
//   - vdb:     VDB's check-packages endpoint — CVEs plus slopsquatting and
//     MCP registry signals in one call; selected automatically when
//     VDB_API_KEY is set, or explicitly with --vuln-source vdb
//   - fixture: an offline JSON file for tests and demos
//
// Any network failure disables enrichment and the scan still completes.
package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/model"
	"github.com/junseok-seo/sbomcmp/internal/osv"
	"github.com/junseok-seo/sbomcmp/internal/purl"
	"github.com/junseok-seo/sbomcmp/internal/vdb"
)

// Config selects the source.
type Config struct {
	Source            string // auto | osv | vdb | none
	OSVEndpoint       string // OSV-compatible base URL (default api.osv.dev)
	VDBEndpoint       string // VDB origin (default https://vdb.ai.kr)
	VDBKey            string // VDB bearer token (VDB_API_KEY)
	Fixture           string // offline fixture path
	Timeout           time.Duration
	OnlyDisagreements bool // only query rows not seen by every tool
	Log               func(string)
}

// Resolve returns the effective source name.
func (c Config) Resolve() string {
	switch {
	case c.Fixture != "":
		return "fixture"
	case c.Source == "none":
		return "none"
	case c.Source == "vdb", c.Source == "osv":
		return c.Source
	case c.VDBKey != "":
		return "vdb"
	default:
		return "osv"
	}
}

// QueryPurl is the purl sent to vulnerability databases for a row.
func QueryPurl(r model.Row) string {
	return purl.QueryString(purl.PURL{Type: r.Type, Namespace: r.Namespace, Name: r.Name, Version: r.Version})
}

// Enrich mutates rows in place and fills meta.
func Enrich(ctx context.Context, cfg Config, rows []model.Row, meta *model.VulnMeta) {
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	// With a single generator every row is trivially "all"; there is no
	// disagreement set, so query everything.
	onlyDis := cfg.OnlyDisagreements
	for _, r := range rows {
		if len(r.Cells) == 1 {
			onlyDis = false
		}
		break
	}
	var idx []int
	for i, r := range rows {
		if onlyDis && r.Agreement == "all" {
			continue
		}
		if r.Type == "unknown" || r.Version == "" {
			continue
		}
		idx = append(idx, i)
	}
	meta.Queried = len(idx)
	meta.Source = cfg.Resolve()

	var err error
	switch meta.Source {
	case "none":
		meta.Queried = 0
		return
	case "fixture":
		meta.Endpoint = cfg.Fixture
		err = fromFixture(cfg.Fixture, rows, idx, meta)
	case "vdb":
		c := vdb.New(cfg.VDBEndpoint, cfg.VDBKey, cfg.Timeout)
		meta.Endpoint = c.Endpoint
		meta.Anonymous = cfg.VDBKey == ""
		if meta.Anonymous {
			cfg.Log(fmt.Sprintf("[vuln] VDB without a key: %d packages per request on an hourly quota — set VDB_API_KEY for full coverage", vdb.AnonymousBatch))
		}
		err = fromVDB(ctx, c, rows, idx, meta)
	default:
		c := osv.New(cfg.OSVEndpoint, "", cfg.Timeout)
		meta.Endpoint = c.Endpoint
		var st osv.Stats
		st, err = c.Enrich(ctx, rows, idx, QueryPurl, "osv")
		meta.Answered = st.Answered
		meta.DetailsCapped = st.DetailsCapped
		if st.DetailsCapped > 0 {
			meta.Note = fmt.Sprintf("%d advisories were not scored (OSV detail cap of %d); shown as UNKNOWN", st.DetailsCapped, c.MaxDetails)
		}
	}
	if err != nil {
		meta.Error = err.Error()
		meta.Answered = 0
		cfg.Log("[vuln] disabled: " + err.Error())
		return
	}
	meta.Enabled = true
	meta.Hits = 0
	for _, i := range idx {
		if len(rows[i].Vulns) > 0 {
			meta.Hits++
		}
	}
}

func fromVDB(ctx context.Context, c *vdb.Client, rows []model.Row, idx []int, meta *model.VulnMeta) error {
	purls := make([]string, len(idx))
	for k, i := range idx {
		purls[k] = QueryPurl(rows[i])
	}
	res, quota, err := c.Check(ctx, purls)
	answered := 0
	for k, i := range idx {
		if res[k] != nil {
			answered++
			vdb.Apply(&rows[i], res[k])
		}
	}
	if err != nil && answered == 0 {
		return err
	}
	meta.Answered = answered
	meta.VDBExtras = true
	if answered < len(idx) {
		meta.Note = fmt.Sprintf("VDB answered %d of %d queries", answered, len(idx))
		if quota != nil && !quota.Authenticated {
			meta.Note += fmt.Sprintf(" (anonymous quota: %d/hour, %d left)", quota.LimitPerHour, quota.Remaining)
		}
		if err != nil {
			meta.Note += "; " + err.Error()
		}
	}
	return nil
}

// EnrichMCP checks discovered MCP servers against VDB's registry. It is a
// no-op unless the resolved source is vdb or a fixture carries "mcp" entries.
func EnrichMCP(ctx context.Context, cfg Config, servers []model.MCPServer, meta *model.VulnMeta) {
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	var idx []int
	for i, s := range servers {
		if s.Package != "" {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return
	}
	switch cfg.Resolve() {
	case "fixture":
		_ = mcpFromFixture(cfg.Fixture, servers, idx)
	case "vdb":
		c := vdb.New(cfg.VDBEndpoint, cfg.VDBKey, cfg.Timeout)
		purls := make([]string, len(idx))
		for k, i := range idx {
			purls[k] = servers[i].Package
		}
		res, _, err := c.Check(ctx, purls)
		if err != nil {
			cfg.Log("[mcp] VDB registry check skipped: " + err.Error())
		}
		for k, i := range idx {
			r := res[k]
			if r == nil {
				continue
			}
			s := &servers[i]
			s.Registry = vdb.Registry(r.MCP)
			if s.Registry == nil {
				s.Registry = &model.MCPRegistry{ID: servers[i].Package, TrustTier: "unverified", Source: "vdb",
					RiskNotes: "not in VDB's MCP registry"}
				s.Signals = append(s.Signals, model.Signal{Kind: "mcp", Level: "warn", Source: "vdb",
					Message: "package is not in VDB's MCP registry — unverified publisher"})
			}
			for _, sig := range vdb.Signals(r) {
				s.Signals = append(s.Signals, sig)
			}
			switch {
			case len(r.Vulns) == 0:
			case r.Version == "":
				// Unpinned launcher: the advisories are for some version of the
				// package, not necessarily the one that will run. One warning.
				ids := make([]string, 0, len(r.Vulns))
				for _, v := range r.Vulns {
					ids = append(ids, v.ID)
				}
				n := max(r.VulnsTotal, len(r.Vulns))
				s.Signals = append(s.Signals, model.Signal{Kind: "advisory", Level: "warn", Source: "vdb",
					Message: fmt.Sprintf("%d known advisories for this package (%s); pin a version to evaluate", n, strings.Join(ids, ", "))})
			default:
				for _, v := range r.Vulns {
					s.Signals = append(s.Signals, model.Signal{Kind: "advisory", Level: levelFor(v.SeverityBucket, v.KEV), Source: "vdb",
						Message: v.ID + " (" + v.SeverityBucket + ") affects " + r.Version})
				}
			}
		}
		if meta != nil {
			meta.VDBExtras = true
		}
	}
}

func levelFor(bucket string, kev bool) string {
	switch {
	case kev, bucket == "critical", bucket == "high":
		return "refuse"
	case bucket == "medium":
		return "warn"
	}
	return "info"
}

// ---- offline fixture ----

type fixture struct {
	Vulns   map[string][]model.Vuln       `json:"vulns"`
	Signals map[string][]model.Signal     `json:"signals"`
	MCP     map[string]*model.MCPRegistry `json:"mcp"` // keyed by server package purl
}

func loadFixture(path string) (*fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fx fixture
	if err := json.Unmarshal(data, &fx); err != nil {
		return nil, err
	}
	return &fx, nil
}

func fromFixture(path string, rows []model.Row, idx []int, meta *model.VulnMeta) error {
	fx, err := loadFixture(path)
	if err != nil {
		return err
	}
	meta.Answered = len(idx)
	for _, i := range idx {
		p := QueryPurl(rows[i])
		if vs, ok := fx.Vulns[p]; ok {
			for _, v := range vs {
				if v.Source == "" {
					v.Source = "fixture"
				}
				rows[i].Vulns = append(rows[i].Vulns, v)
			}
			rows[i].MaxSev = model.MaxSeverity(rows[i].Vulns)
		}
		if ss, ok := fx.Signals[p]; ok {
			rows[i].Signals = append(rows[i].Signals, ss...)
			meta.VDBExtras = true
		}
	}
	return nil
}

func mcpFromFixture(path string, servers []model.MCPServer, idx []int) error {
	fx, err := loadFixture(path)
	if err != nil {
		return err
	}
	for _, i := range idx {
		if reg, ok := fx.MCP[servers[i].Package]; ok && reg != nil {
			r := *reg
			if r.Source == "" {
				r.Source = "fixture"
			}
			servers[i].Registry = &r
			if r.TrustTier == "unverified" {
				servers[i].Signals = append(servers[i].Signals, model.Signal{Kind: "mcp", Level: "warn", Source: r.Source,
					Message: "package is not in the MCP registry — unverified publisher"})
			}
		}
	}
	return nil
}
