package vdb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

// liveShape is a trimmed copy of a real check-packages answer (2026-10).
const liveShape = `{"results":[
 {"input":"pkg:npm/qs@6.11.0","purl":"pkg:npm/qs@6.11.0","version":"6.11.0","matched":true,"risk":"medium","flags":[],
  "registry":{"ecosystem":"npm","name":"qs","exists":true,"downloads":187417749,"risk_hint":"low","rationale":"Established package."},
  "mcp":null,"model":null,
  "vulnerabilities":[{"id":"GHSA-4mjr-xmp4-gh2g","summary":"qs: DoS via isBuffer","severity_bucket":"medium","severity_score":5.3,"fixed_in":["6.16.0"],"kev":false,"epss":0.004}],
  "vulnerabilities_total":3,"safe_upgrade":"6.16.0","agent_action":"CONFIRM","because":"GHSA-4mjr-xmp4-gh2g (medium); fixed in 6.16.0"},
 {"input":"pkg:npm/requests-toolkit-pro@1.2.0","purl":"pkg:npm/requests-toolkit-pro@1.2.0","matched":true,"risk":"not_found","flags":[],
  "registry":{"ecosystem":"npm","name":"requests-toolkit-pro","exists":false,"risk_hint":"not_found","rationale":"Name does not exist on the npm registry."},
  "mcp":null,"vulnerabilities":[],"vulnerabilities_total":0,"agent_action":"REFUSE","because":"this name does not exist on the registry"},
 {"input":"pkg:npm/@modelcontextprotocol/server-filesystem","purl":"pkg:npm/@modelcontextprotocol/server-filesystem","matched":true,"risk":"low","flags":[],
  "registry":{"ecosystem":"npm","name":"@modelcontextprotocol/server-filesystem","exists":true,"risk_hint":"low"},
  "mcp":{"id":"mcp:anthropic/filesystem","display_name":"Filesystem (Anthropic)","trust_tier":"official","scopes":["fs:read","fs:write"],"risk_score":0.12,"risk_notes":"Can write to the host filesystem.","scope_drift":null},
  "vulnerabilities":[],"vulnerabilities_total":0,"agent_action":"PROCEED","because":"no known advisory or slop signal"}
],"agent_action":"REFUSE","anonymous":{"authenticated":false,"limit_per_hour":20,"remaining":19,"resets_in_seconds":1479}}`

func TestCheckParsesLiveShapeAndBatches(t *testing.T) {
	var calls int
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/ai/check-packages" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("anonymous call must not send Authorization")
		}
		var req struct {
			Packages []string `json:"packages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		sizes = append(sizes, len(req.Packages))
		w.Write([]byte(liveShape))
	}))
	defer srv.Close()

	c := New(srv.URL, "", 0)
	c.Batch = 3
	purls := []string{"pkg:npm/qs@6.11.0", "pkg:npm/requests-toolkit-pro@1.2.0", "pkg:npm/@modelcontextprotocol/server-filesystem", "pkg:npm/x@1"}
	res, quota, err := c.Check(context.Background(), purls)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || sizes[0] != 3 || sizes[1] != 1 {
		t.Fatalf("batching: calls=%d sizes=%v", calls, sizes)
	}
	if quota == nil || quota.Remaining != 19 {
		t.Fatalf("quota not parsed: %+v", quota)
	}
	row := model.Row{Key: "npm/qs@6.11.0"}
	Apply(&row, res[0])
	if len(row.Vulns) != 1 || row.Vulns[0].Severity != "MEDIUM" || row.Vulns[0].Fixed != "6.16.0" || row.VulnTotal != 3 || row.MaxSev != "MEDIUM" || row.Vulns[0].Source != "vdb" {
		t.Fatalf("qs row: %+v", row)
	}
	sig := Signals(res[1])
	if len(sig) != 1 || sig[0].Kind != "slopsquat" || sig[0].Level != "refuse" {
		t.Fatalf("slopsquat signal: %+v", sig)
	}
	reg := Registry(res[2].MCP)
	if reg == nil || reg.TrustTier != "official" || len(reg.Scopes) != 2 || reg.RiskScore != 0.12 {
		t.Fatalf("mcp registry: %+v", reg)
	}
	if s := Signals(res[2]); len(s) != 1 || s[0].Kind != "mcp" || s[0].Level != "info" {
		t.Fatalf("mcp signal: %+v", s)
	}
}

func TestCheckSendsBearerAndStopsOnQuota(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vdb_test" {
			t.Errorf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		w.Write([]byte(`{"results":[{"input":"a","risk":"low"}],"agent_action":"PROCEED","anonymous":{"remaining":0}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "vdb_test", 0)
	c.Batch = 1
	res, _, err := c.Check(context.Background(), []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if res[0] == nil || res[1] != nil || res[2] != nil {
		t.Fatalf("expected to stop after quota hit 0: %v", res)
	}
}
