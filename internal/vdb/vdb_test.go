package vdb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
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
,
 {"input":"pkg:npm/chalk@2.4.2","purl":"pkg:npm/chalk@2.4.2","version":"2.4.2","matched":true,"risk":"high","flags":[],"registry":null,"mcp":null,
  "vulnerabilities":[{"id":"MAL-2025-46969","summary":"Malicious code in chalk (npm)","severity_bucket":"critical","severity_score":null,"fixed_in":[],"kev":false,"epss":null,"malicious":true,"severity_source":"malicious"}],
  "vulnerabilities_total":1,"worst_bucket":"critical","malicious":true,"agent_action":"REFUSE","because":"MAL-2025-46969 is a malicious package report"},
 {"input":"pkg:npm/trunc@1","purl":"pkg:npm/trunc@1","version":"1","matched":true,"risk":"high","flags":[],"registry":null,"mcp":null,
  "vulnerabilities":[{"id":"GHSA-low","severity_bucket":"low","severity_score":3.1,"fixed_in":["2"],"kev":false,"epss":0.9}],
  "vulnerabilities_total":4,"worst_bucket":"critical","agent_action":"REFUSE","because":"x"}
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
		// Answer aligned with the request, like VDB does.
		var canned struct {
			Results   []json.RawMessage `json:"results"`
			Anonymous json.RawMessage   `json:"anonymous"`
		}
		json.Unmarshal([]byte(liveShape), &canned)
		byInput := map[string]json.RawMessage{}
		for _, raw := range canned.Results {
			var r struct{ Input string }
			json.Unmarshal(raw, &r)
			byInput[r.Input] = raw
		}
		out := []json.RawMessage{}
		for _, pkg := range req.Packages {
			if raw, ok := byInput[pkg]; ok {
				out = append(out, raw)
			} else {
				out = append(out, json.RawMessage(`{"input":"`+pkg+`","risk":"unknown"}`))
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": out, "agent_action": "REFUSE", "anonymous": canned.Anonymous})
	}))
	defer srv.Close()

	c := New(srv.URL, "", 0)
	c.Batch = 3
	purls := []string{"pkg:npm/qs@6.11.0", "pkg:npm/requests-toolkit-pro@1.2.0", "pkg:npm/@modelcontextprotocol/server-filesystem", "pkg:npm/chalk@2.4.2", "pkg:npm/trunc@1", "pkg:npm/x@1"}
	res, quota, err := c.Check(context.Background(), purls)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || sizes[0] != 3 || sizes[1] != 3 {
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
	mal := model.Row{Key: "npm/chalk@2.4.2"}
	Apply(&mal, res[3])
	if !mal.HasMalicious() || mal.MaxSev != "CRITICAL" || len(mal.Signals) != 1 || mal.Signals[0].Kind != "malicious" || mal.Signals[0].Level != "refuse" {
		t.Fatalf("malicious row: %+v", mal)
	}
	tr := model.Row{Key: "npm/trunc@1"}
	Apply(&tr, res[4])
	if tr.MaxSev != "CRITICAL" || tr.VulnTotal != 4 || len(tr.Vulns) != 1 {
		t.Fatalf("worst_bucket should raise MaxSev over the truncated list: %+v", tr)
	}
}

func TestCheckKeyedRunsAllBatchesWithBearer(t *testing.T) {
	var mu sync.Mutex
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vdb_test" {
			t.Errorf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		var req struct {
			Packages []string `json:"packages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		calls++
		mu.Unlock()
		res := make([]map[string]any, 0, len(req.Packages))
		for _, p := range req.Packages {
			res = append(res, map[string]any{"input": p, "risk": "low"})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res, "agent_action": "PROCEED"})
	}))
	defer srv.Close()
	c := New(srv.URL, "vdb_test", 0)
	c.Batch = 2
	purls := []string{"a", "b", "c", "d", "e"}
	res, quota, err := c.Check(context.Background(), purls)
	if err != nil || quota != nil {
		t.Fatalf("err=%v quota=%v", err, quota)
	}
	if calls != 3 {
		t.Fatalf("expected 3 batches, got %d", calls)
	}
	for i, p := range purls {
		if res[i] == nil || res[i].Input != p {
			t.Fatalf("result %d misaligned: %+v", i, res[i])
		}
	}
}

func TestCheckSplitsBatchOn5xx(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Packages []string `json:"packages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		sizes = append(sizes, len(req.Packages))
		mu.Unlock()
		if len(req.Packages) > 2 {
			http.Error(w, "upstream timeout", http.StatusBadGateway)
			return
		}
		res := make([]map[string]any, 0, len(req.Packages))
		for _, p := range req.Packages {
			res = append(res, map[string]any{"input": p, "risk": "low"})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res, "agent_action": "PROCEED"})
	}))
	defer srv.Close()
	c := New(srv.URL, "vdb_test", 0)
	c.Batch = 4
	res, _, err := c.Check(context.Background(), []string{"a", "b", "c", "d"})
	if err != nil {
		t.Fatalf("halves should have succeeded: %v", err)
	}
	for i := range res {
		if res[i] == nil {
			t.Fatalf("result %d missing after split retry", i)
		}
	}
	if len(sizes) != 3 || sizes[0] != 4 {
		t.Fatalf("expected one 4-batch then two halves, got %v", sizes)
	}
}

func TestCheckAnonymousStopsOnQuota(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"input":"a","risk":"low"}],"agent_action":"PROCEED","anonymous":{"remaining":0}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "", 0)
	c.Batch = 1
	res, quota, err := c.Check(context.Background(), []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if res[0] == nil || res[1] != nil || res[2] != nil || quota == nil || quota.Remaining != 0 {
		t.Fatalf("expected to stop after quota hit 0: %v %v", res, quota)
	}
}
