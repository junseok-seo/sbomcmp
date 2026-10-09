// Package cdx parses CycloneDX JSON (1.4–1.6) into normalized components.
// It also accepts SPDX 2.x JSON as a fallback so that generators that only
// emit SPDX can still participate.
package cdx

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/junseok-seo/sbomcmp/internal/model"
	"github.com/junseok-seo/sbomcmp/internal/purl"
)

type cdxDoc struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Metadata    *cdxMetadata   `json:"metadata"`
	Components  []cdxComponent `json:"components"`
	// SPDX fallback
	SPDXID   string        `json:"SPDXID"`
	Packages []spdxPackage `json:"packages"`
}

type cdxMetadata struct {
	Component *cdxComponent   `json:"component"`
	Tools     json.RawMessage `json:"tools"`
}

type cdxComponent struct {
	Type       string         `json:"type"`
	BOMRef     string         `json:"bom-ref"`
	Group      string         `json:"group"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	Purl       string         `json:"purl"`
	Scope      string         `json:"scope"`
	Licenses   []cdxLicense   `json:"licenses"`
	Properties []cdxProperty  `json:"properties"`
	Components []cdxComponent `json:"components"` // nested
}

type cdxLicense struct {
	License    *struct{ ID, Name string } `json:"license"`
	Expression string                     `json:"expression"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type spdxPackage struct {
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	ExternalRefs     []struct {
		ReferenceType    string `json:"referenceType"`
		ReferenceLocator string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

// Parse decodes a CycloneDX (or SPDX) JSON document into components.
// The second return value is a short description of the format detected and
// the third the number of version-less entries that were skipped: a component
// without a version (typically the scanned module itself) cannot be compared
// or looked up, so it is counted rather than turned into a row.
func Parse(data []byte) ([]model.Component, string, int, error) {
	var doc cdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", 0, fmt.Errorf("decode: %w", err)
	}
	if doc.BOMFormat == "CycloneDX" || len(doc.Components) > 0 {
		out := make([]model.Component, 0, len(doc.Components))
		skipped := 0
		walk(doc.Components, &out, &skipped)
		return dedupe(out), "cyclonedx-" + doc.SpecVersion, skipped, nil
	}
	if doc.SPDXID != "" || len(doc.Packages) > 0 {
		out := make([]model.Component, 0, len(doc.Packages))
		skipped := 0
		for _, p := range doc.Packages {
			if p.Name == "" {
				continue
			}
			if p.VersionInfo == "" || p.VersionInfo == "NOASSERTION" {
				skipped++
				continue
			}
			var pu string
			for _, r := range p.ExternalRefs {
				if r.ReferenceType == "purl" {
					pu = r.ReferenceLocator
					break
				}
			}
			c := build(pu, "", p.Name, p.VersionInfo, "", nil)
			lic := p.LicenseConcluded
			if lic == "" || lic == "NOASSERTION" {
				lic = p.LicenseDeclared
			}
			if lic != "" && lic != "NOASSERTION" {
				c.Licenses = []string{lic}
			}
			out = append(out, c)
		}
		return dedupe(out), "spdx", skipped, nil
	}
	return nil, "", 0, fmt.Errorf("unrecognized document (no bomFormat / SPDXID)")
}

func walk(cs []cdxComponent, out *[]model.Component, skipped *int) {
	for _, c := range cs {
		// Skip non-package entries (files, operating-system metadata) but keep libraries,
		// applications, frameworks and OS packages.
		switch strings.ToLower(c.Type) {
		case "file", "device", "firmware", "container", "data":
			if c.Purl == "" {
				continue
			}
		}
		// Trivy and others emit purl-less, version-less "application" nodes for
		// each manifest (go.mod, requirements.txt). They are structure, not packages.
		if c.Purl == "" && c.Version == "" {
			if len(c.Components) > 0 {
				walk(c.Components, out, skipped)
			}
			continue
		}
		// A purl without a version (e.g. the scanned Go module itself) cannot be
		// compared across tools; count it instead of making a row.
		if c.Version == "" && !strings.Contains(c.Purl[strings.LastIndex(c.Purl, "/")+1:], "@") {
			*skipped++
			if len(c.Components) > 0 {
				walk(c.Components, out, skipped)
			}
			continue
		}
		props := map[string]string{}
		for _, p := range c.Properties {
			// Keep the handful of properties that explain disagreements.
			n := strings.ToLower(p.Name)
			if strings.Contains(n, "scope") || strings.Contains(n, "cataloger") ||
				strings.Contains(n, "pkgtype") || strings.Contains(n, "foundby") ||
				strings.Contains(n, "development") || strings.Contains(n, "layer") ||
				strings.Contains(n, "location") || strings.Contains(n, "srcfile") ||
				strings.Contains(n, "filepath") {
				props[p.Name] = p.Value
			}
		}
		var lics []string
		for _, l := range c.Licenses {
			if l.Expression != "" {
				lics = append(lics, l.Expression)
			} else if l.License != nil {
				if l.License.ID != "" {
					lics = append(lics, l.License.ID)
				} else if l.License.Name != "" {
					lics = append(lics, l.License.Name)
				}
			}
		}
		comp := build(c.Purl, c.Group, c.Name, c.Version, c.Scope, props)
		comp.Licenses = lics
		// cdxgen marks dev deps via properties; Syft via scope-less; Trivy via no marker.
		if comp.Scope == "" {
			for k, v := range props {
				lk := strings.ToLower(k)
				if (strings.Contains(lk, "development") || strings.Contains(lk, "scope")) &&
					(v == "true" || strings.EqualFold(v, "dev") || strings.EqualFold(v, "test")) {
					comp.Scope = "dev"
				}
			}
		}
		*out = append(*out, comp)
		if len(c.Components) > 0 {
			walk(c.Components, out, skipped)
		}
	}
}

func build(rawPurl, group, name, version, scope string, props map[string]string) model.Component {
	var p purl.PURL
	if rawPurl != "" {
		p = purl.Normalize(purl.Parse(rawPurl))
	} else {
		// Guess type from props if possible.
		typ := ""
		for k, v := range props {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "pkgtype") || strings.Contains(lk, "type") {
				typ = strings.ToLower(v)
			}
		}
		n := name
		if group != "" {
			n = group + "/" + name
		}
		p = purl.FromNameVersion(typ, n, version)
	}
	if p.Version == "" && version != "" {
		p.Version = version
	}
	if p.Name == "" {
		p.Name = name
	}
	return model.Component{
		Key:       purl.Key(p),
		NameKey:   purl.NameKey(p),
		Type:      p.Type,
		Namespace: p.Namespace,
		Name:      p.Name,
		Version:   p.Version,
		Purl:      rawPurl,
		Scope:     strings.ToLower(scope),
		Props:     props,
	}
}

// dedupe collapses identical keys within one document (tools often list the
// same package once per location/layer).
func dedupe(in []model.Component) []model.Component {
	seen := map[string]int{}
	out := make([]model.Component, 0, len(in))
	for _, c := range in {
		if i, ok := seen[c.Key]; ok {
			// Merge licenses & keep first props.
			out[i].Licenses = mergeStr(out[i].Licenses, c.Licenses)
			if out[i].Scope == "" {
				out[i].Scope = c.Scope
			}
			continue
		}
		seen[c.Key] = len(out)
		out = append(out, c)
	}
	return out
}

func mergeStr(a, b []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range append(a, b...) {
		if s == "" || m[s] {
			continue
		}
		m[s] = true
		out = append(out, s)
	}
	return out
}
