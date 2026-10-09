package vdb

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scanShape is the shape of a /v1/sbom/scan answer with a few extra fields
// a newer server might add.
const scanShape = `{"agent_action":"CONFIRM","summary":{"critical":1,"high":2,"medium":0,"low":1,"total":4,"future_bucket":"n/a"},
"components_total":42,"components_truncated":false,"request_id":"abc",
"vulnerabilities":[
 {"id":"CVE-2024-0001","package":"pkg:npm/qs@6.11.0","severity":"high","severity_score":7.5,"fixed_in":["6.16.0"],"kev":true,"epss":0.4},
 {"id":"GHSA-xxxx","purl":"pkg:pypi/flask@2.0.0","severity_bucket":"critical","fixed_in":"2.3.2","extra":{"nested":true}},
 {"id":"OSV-1","name":"left-pad","version":"1.0.0","severity":"low"}
]}`

// sbomServer records the last multipart upload and answers each path with a
// canned status and body.
func sbomServer(t *testing.T, answers map[string]struct {
	status int
	body   string
}) (*httptest.Server, *struct {
	path, auth, field, filename, content string
}) {
	t.Helper()
	got := &struct{ path, auth, field, filename, content string }{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.auth = r.Header.Get("Authorization")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("multipart parse: %v", err)
			http.Error(w, "bad multipart", 400)
			return
		}
		for field, files := range r.MultipartForm.File {
			got.field = field
			got.filename = files[0].Filename
			f, _ := files[0].Open()
			data, _ := io.ReadAll(f)
			got.content = string(data)
		}
		a, ok := answers[r.URL.Path]
		if !ok {
			http.Error(w, "unexpected path "+r.URL.Path, 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.status)
		io.WriteString(w, a.body)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestScanSBOM(t *testing.T) {
	srv, got := sbomServer(t, map[string]struct {
		status int
		body   string
	}{"/v1/sbom/scan": {200, scanShape}})
	c := New(srv.URL, "vdb_test", 0)
	r, err := c.ScanSBOM(context.Background(), "sample-project-cdxgen.cdx.json", []byte(`{"bomFormat":"CycloneDX"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/v1/sbom/scan" || got.auth != "Bearer vdb_test" {
		t.Errorf("request: path %q auth %q", got.path, got.auth)
	}
	if got.field != "file" || got.filename != "sample-project-cdxgen.cdx.json" {
		t.Errorf("multipart: field %q filename %q", got.field, got.filename)
	}
	if !strings.Contains(got.content, "CycloneDX") {
		t.Errorf("file content not forwarded: %q", got.content)
	}
	if r.AgentAction != "CONFIRM" || r.ComponentsTotal != 42 || bool(r.ComponentsTruncated) {
		t.Errorf("header fields: %+v", r)
	}
	if r.Summary.Critical != 1 || r.Summary.High != 2 || r.Summary.Low != 1 || r.Summary.Total != 4 {
		t.Errorf("summary: %+v", r.Summary)
	}
	if len(r.Vulnerabilities) != 3 {
		t.Fatalf("want 3 vulnerabilities, got %d", len(r.Vulnerabilities))
	}
	v := r.Vulnerabilities
	if v[0].Subject() != "pkg:npm/qs@6.11.0" || v[0].Bucket() != "HIGH" || v[0].FixedVersion() != "6.16.0" || !v[0].KEV {
		t.Errorf("v0: %+v", v[0])
	}
	if v[1].Subject() != "pkg:pypi/flask@2.0.0" || v[1].Bucket() != "CRITICAL" || v[1].FixedVersion() != "2.3.2" {
		t.Errorf("v1 (string fixed_in, severity_bucket): %+v", v[1])
	}
	if v[2].Subject() != "left-pad@1.0.0" || v[2].Bucket() != "LOW" || v[2].FixedVersion() != "" {
		t.Errorf("v2 (name+version, no fix): %+v", v[2])
	}
}

func TestScanSBOMMissingFieldsAreZero(t *testing.T) {
	srv, _ := sbomServer(t, map[string]struct {
		status int
		body   string
	}{"/v1/sbom/scan": {200, `{"agent_action":"PROCEED","summary":"none","components_truncated":1}`}})
	r, err := New(srv.URL, "k", 0).ScanSBOM(context.Background(), "x.cdx.json", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Summary.Empty() || r.ComponentsTotal != 0 || len(r.Vulnerabilities) != 0 || !bool(r.ComponentsTruncated) {
		t.Errorf("tolerant decode: %+v", r)
	}
}

func TestScanSBOMTooLarge(t *testing.T) {
	srv, _ := sbomServer(t, map[string]struct {
		status int
		body   string
	}{"/v1/sbom/scan": {413, `{"error":"payload_too_large","message":"SBOM exceeds 5 MB"}`}})
	_, err := New(srv.URL, "k", 0).ScanSBOM(context.Background(), "x.cdx.json", make([]byte, 3000))
	if err == nil || !IsHTTPStatus(err, 413) {
		t.Fatalf("want a 413 error, got %v", err)
	}
	if !strings.Contains(err.Error(), "too large") || !strings.Contains(err.Error(), "SBOM exceeds 5 MB") || !strings.Contains(err.Error(), "3 KB") {
		t.Errorf("message: %v", err)
	}
}

func TestScanSBOMBadKey(t *testing.T) {
	srv, _ := sbomServer(t, map[string]struct {
		status int
		body   string
	}{"/v1/sbom/scan": {401, `{"detail":"invalid api key"}`}})
	_, err := New(srv.URL, "k", 0).ScanSBOM(context.Background(), "x.cdx.json", []byte("{}"))
	if err == nil || !IsHTTPStatus(err, 401) || !strings.Contains(err.Error(), "signup") {
		t.Fatalf("want a 401 error with the sign-up hint, got %v", err)
	}
}

func TestRegisterWatch(t *testing.T) {
	srv, got := sbomServer(t, map[string]struct {
		status int
		body   string
	}{"/v1/sbom/watches": {201, `{"id":17,"name":"sample-project-cdxgen.cdx.json","filename":"sample-project-cdxgen.cdx.json","component_count":42,"created_at":"2026-10-09T00:00:00Z"}`}})
	w, err := New(srv.URL, "vdb_test", 0).RegisterWatch(context.Background(), "sample-project-cdxgen.cdx.json", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/v1/sbom/watches" || got.auth != "Bearer vdb_test" || got.field != "file" || got.filename != "sample-project-cdxgen.cdx.json" {
		t.Errorf("request: %+v", got)
	}
	if w.ID != "17" || w.Name != "sample-project-cdxgen.cdx.json" || w.ComponentCount != 42 {
		t.Errorf("watch: %+v", w)
	}
}

func TestRegisterWatchLimit(t *testing.T) {
	srv, _ := sbomServer(t, map[string]struct {
		status int
		body   string
	}{"/v1/sbom/watches": {403, `{"error":"watch_limit_reached","message":"free accounts can watch 3 SBOMs","limit":3}`}})
	_, err := New(srv.URL, "k", 0).RegisterWatch(context.Background(), "x.cdx.json", []byte("{}"))
	var le *WatchLimitError
	if !errors.As(err, &le) {
		t.Fatalf("want *WatchLimitError, got %T %v", err, err)
	}
	if le.Limit != 3 || !strings.Contains(le.Error(), "3 SBOM") {
		t.Errorf("limit error: limit %d msg %q", le.Limit, le.Error())
	}
}

func TestRegisterWatchTooLarge(t *testing.T) {
	srv, _ := sbomServer(t, map[string]struct {
		status int
		body   string
	}{"/v1/sbom/watches": {413, `{"error":"payload_too_large"}`}})
	_, err := New(srv.URL, "k", 0).RegisterWatch(context.Background(), "x.cdx.json", []byte("{}"))
	if err == nil || !IsHTTPStatus(err, 413) {
		t.Fatalf("want a 413 error, got %v", err)
	}
}
