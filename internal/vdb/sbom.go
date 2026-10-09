package vdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
)

// ScanResult is the answer of POST /v1/sbom/scan: one verdict for a whole
// SBOM. Fields VDB does not send stay zero; fields it adds are ignored.
type ScanResult struct {
	AgentAction         string     `json:"agent_action"` // REFUSE / CONFIRM / PROCEED
	Summary             Counts     `json:"summary"`
	Vulnerabilities     []ScanVuln `json:"vulnerabilities"`
	ComponentsTotal     int        `json:"components_total"`
	ComponentsTruncated FlexBool   `json:"components_truncated"`
}

// ScanVuln is one finding of a scan.
type ScanVuln struct {
	ID             string   `json:"id"`
	Package        string   `json:"package"`
	Purl           string   `json:"purl"`
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Severity       string   `json:"severity"`
	SeverityBucket string   `json:"severity_bucket"`
	Score          float64  `json:"severity_score"`
	Fixed          FlexList `json:"fixed"`
	FixedIn        FlexList `json:"fixed_in"`
	KEV            bool     `json:"kev"`
	EPSS           *float64 `json:"epss"`
	Malicious      bool     `json:"malicious"`
}

// Subject names the affected package the way the server put it.
func (v ScanVuln) Subject() string {
	if v.Purl != "" {
		return v.Purl
	}
	if v.Package != "" {
		if v.Version != "" && !strings.Contains(v.Package, "@"+v.Version) {
			return v.Package + "@" + v.Version
		}
		return v.Package
	}
	if v.Name != "" && v.Version != "" {
		return v.Name + "@" + v.Version
	}
	return v.Name
}

// Bucket is the severity as sbomcmp spells it.
func (v ScanVuln) Bucket() string { return bucket(firstNonEmpty(v.SeverityBucket, v.Severity)) }

// FixedVersion is the first fixed version named, or "".
func (v ScanVuln) FixedVersion() string {
	if len(v.FixedIn) > 0 {
		return v.FixedIn[0]
	}
	if len(v.Fixed) > 0 {
		return v.Fixed[0]
	}
	return ""
}

// Counts is a summary block: severity → count. VDB sends an object; the
// keys it uses are read case-insensitively and anything that is not a
// number is skipped, so a changed shape degrades to zeros, not an error.
type Counts struct {
	Critical, High, Medium, Low, Unknown int
	Total                                int
	Other                                map[string]int
}

// UnmarshalJSON accepts an object of counts (any other shape is ignored).
func (c *Counts) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	for k, raw := range m {
		var f float64
		if json.Unmarshal(raw, &f) != nil {
			var s string
			if json.Unmarshal(raw, &s) != nil {
				continue
			}
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				continue
			}
			f = v
		}
		n := int(f)
		switch strings.ToLower(k) {
		case "critical":
			c.Critical = n
		case "high":
			c.High = n
		case "medium", "moderate":
			c.Medium = n
		case "low":
			c.Low = n
		case "unknown":
			c.Unknown = n
		case "total", "vulnerabilities", "vulnerabilities_total", "count":
			c.Total = n
		default:
			if c.Other == nil {
				c.Other = map[string]int{}
			}
			c.Other[k] = n
		}
	}
	return nil
}

// Empty is true when no severity count was read.
func (c Counts) Empty() bool {
	return c.Critical == 0 && c.High == 0 && c.Medium == 0 && c.Low == 0 && c.Unknown == 0 && c.Total == 0
}

// Add counts one finding.
func (c *Counts) Add(bucket string) {
	switch bucket {
	case "CRITICAL":
		c.Critical++
	case "HIGH":
		c.High++
	case "MEDIUM":
		c.Medium++
	case "LOW":
		c.Low++
	default:
		c.Unknown++
	}
	c.Total++
}

// Watch is an entry of /v1/sbom/watches.
type Watch struct {
	ID             FlexString `json:"id"`
	Name           string     `json:"name"`
	Filename       string     `json:"filename"`
	ComponentCount int        `json:"component_count"`
}

// WatchLimitError is the server's refusal to add a watch because the
// account's quota is used up.
type WatchLimitError struct {
	Limit   int
	Message string
}

func (e *WatchLimitError) Error() string {
	if e.Limit > 0 {
		return fmt.Sprintf("watch limit reached: this account can watch %d SBOM(s); remove one at %s/sbom-scan or upgrade the plan", e.Limit, DefaultEndpoint)
	}
	return firstNonEmpty(e.Message, "watch limit reached")
}

// ScanSBOM uploads a CycloneDX document to /v1/sbom/scan and returns its verdict.
func (c *Client) ScanSBOM(ctx context.Context, filename string, sbom []byte) (*ScanResult, error) {
	status, data, err := c.postSBOM(ctx, "/v1/sbom/scan", filename, sbom)
	if err != nil {
		return nil, err
	}
	if err := sbomStatusError("sbom/scan", status, data, len(sbom)); err != nil {
		return nil, err
	}
	var r ScanResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("sbom/scan decode: %w", err)
	}
	return &r, nil
}

// RegisterWatch uploads a CycloneDX document to /v1/sbom/watches so VDB
// re-checks it as advisories arrive. A used-up quota comes back as
// *WatchLimitError.
func (c *Client) RegisterWatch(ctx context.Context, filename string, sbom []byte) (*Watch, error) {
	status, data, err := c.postSBOM(ctx, "/v1/sbom/watches", filename, sbom)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		var body struct {
			Error   string          `json:"error"`
			Message string          `json:"message"`
			Detail  json.RawMessage `json:"detail"`
			Limit   json.RawMessage `json:"limit"`
		}
		_ = json.Unmarshal(data, &body)
		if body.Error == "watch_limit_reached" {
			msg := body.Message
			if msg == "" {
				var d string
				if json.Unmarshal(body.Detail, &d) == nil {
					msg = d
				}
			}
			return nil, &WatchLimitError{Limit: flexInt(body.Limit), Message: msg}
		}
		return nil, sbomStatusError("sbom/watches", status, data, len(sbom))
	}
	var w Watch
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("sbom/watches decode: %w", err)
	}
	if w.ID == "" {
		// Some deployments wrap the item.
		var wrapped struct {
			Watch *Watch `json:"watch"`
			Item  *Watch `json:"item"`
			Data  *Watch `json:"data"`
		}
		if json.Unmarshal(data, &wrapped) == nil {
			for _, inner := range []*Watch{wrapped.Watch, wrapped.Item, wrapped.Data} {
				if inner != nil && inner.ID != "" {
					return inner, nil
				}
			}
		}
	}
	return &w, nil
}

func (c *Client) postSBOM(ctx context.Context, path, filename string, sbom []byte) (int, []byte, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return 0, nil, err
	}
	if _, err := part.Write(sbom); err != nil {
		return 0, nil, err
	}
	if err := mw.Close(); err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+path, &buf)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	c.authorize(req)
	resp, err := c.http().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%s: %w", path, err)
	}
	return resp.StatusCode, data, nil
}

func (c *Client) authorize(req *http.Request) {
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// sbomStatusError turns a non-2xx answer of the SBOM endpoints into an error.
func sbomStatusError(what string, status int, data []byte, size int) error {
	switch {
	case status/100 == 2:
		return nil
	case status == 401 || status == 403:
		return &httpError{status: status, msg: fmt.Sprintf("%s: HTTP %d — VDB rejected the API key (VDB_API_KEY; free at %s/signup)", what, status, DefaultEndpoint)}
	case status == 413:
		msg := fmt.Sprintf("%s: HTTP 413 — the SBOM is too large for VDB", what)
		if size > 0 {
			msg = fmt.Sprintf("%s: HTTP 413 — the SBOM (%d KB) is too large for VDB", what, (size+1023)/1024)
		}
		if detail := errorDetail(data); detail != "" {
			msg += ": " + detail
		}
		return &httpError{status: 413, msg: msg}
	default:
		msg := fmt.Sprintf("%s: HTTP %d", what, status)
		if detail := errorDetail(data); detail != "" {
			msg += ": " + detail
		}
		return &httpError{status: status, msg: msg}
	}
}

// errorDetail pulls the human part out of an error body.
func errorDetail(data []byte) string {
	var body struct {
		Error   string          `json:"error"`
		Message string          `json:"message"`
		Detail  json.RawMessage `json:"detail"`
	}
	if json.Unmarshal(data, &body) == nil {
		var detail string
		if body.Detail != nil && json.Unmarshal(body.Detail, &detail) != nil {
			detail = string(body.Detail)
		}
		if s := firstNonEmpty(body.Message, detail, body.Error); s != "" {
			return truncate(s, 200)
		}
	}
	return truncate(strings.TrimSpace(string(data)), 200)
}

// IsHTTPStatus reports whether err is a VDB answer with the given status.
func IsHTTPStatus(err error, status int) bool {
	var he *httpError
	return errors.As(err, &he) && he.status == status
}

// FlexBool reads true/false, 0/1 or a count as a boolean.
type FlexBool bool

func (b *FlexBool) UnmarshalJSON(data []byte) error {
	var v bool
	if json.Unmarshal(data, &v) == nil {
		*b = FlexBool(v)
		return nil
	}
	var f float64
	if json.Unmarshal(data, &f) == nil {
		*b = f != 0
	}
	return nil
}

// FlexString reads a string or a number as a string.
type FlexString string

func (s *FlexString) UnmarshalJSON(data []byte) error {
	var v string
	if json.Unmarshal(data, &v) == nil {
		*s = FlexString(v)
		return nil
	}
	var n json.Number
	if json.Unmarshal(data, &n) == nil {
		*s = FlexString(n.String())
	}
	return nil
}

// FlexList reads a string, a list of strings, or nothing.
type FlexList []string

func (l *FlexList) UnmarshalJSON(data []byte) error {
	var list []string
	if json.Unmarshal(data, &list) == nil {
		*l = list
		return nil
	}
	var s string
	if json.Unmarshal(data, &s) == nil && s != "" {
		*l = FlexList{s}
	}
	return nil
}

func flexInt(raw json.RawMessage) int {
	if raw == nil {
		return 0
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return int(f)
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		n, _ := strconv.Atoi(s)
		return n
	}
	return 0
}
