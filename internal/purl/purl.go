// Package purl parses and normalizes package URLs so that the same component
// emitted by different generators collapses onto one comparison key.
//
// This is deliberately opinionated: it drops qualifiers and subpaths, lowercases
// where the ecosystem is case-insensitive, and canonicalizes a few well-known
// divergences between Syft, cdxgen and Trivy (v-prefixed Go versions, PyPI name
// separators, npm scope encoding, deb/rpm/apk epoch handling).
package purl

import (
	"net/url"
	"strings"
)

// PURL is a parsed package URL.
type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
	Raw        string
}

// Parse parses a purl. It is tolerant: on malformed input it returns a PURL
// with Type "unknown" and Name set to the raw string, rather than an error.
func Parse(s string) PURL {
	p := PURL{Raw: s, Qualifiers: map[string]string{}}
	rest := strings.TrimSpace(s)
	if !strings.HasPrefix(rest, "pkg:") {
		p.Type = "unknown"
		p.Name = rest
		return p
	}
	rest = strings.TrimPrefix(rest, "pkg:")
	rest = strings.TrimLeft(rest, "/")

	// subpath
	if i := strings.Index(rest, "#"); i >= 0 {
		p.Subpath = rest[i+1:]
		rest = rest[:i]
	}
	// qualifiers
	if i := strings.Index(rest, "?"); i >= 0 {
		q := rest[i+1:]
		rest = rest[:i]
		for _, kv := range strings.Split(q, "&") {
			if kv == "" {
				continue
			}
			k, v, _ := strings.Cut(kv, "=")
			v, _ = url.QueryUnescape(v)
			p.Qualifiers[strings.ToLower(k)] = v
		}
	}
	// version
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		p.Version, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	// type
	if i := strings.Index(rest, "/"); i >= 0 {
		p.Type = strings.ToLower(rest[:i])
		rest = rest[i+1:]
	} else {
		p.Type = strings.ToLower(rest)
		rest = ""
	}
	// namespace / name
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		p.Namespace, _ = url.PathUnescape(rest[:i])
		p.Name, _ = url.PathUnescape(rest[i+1:])
	} else {
		p.Name, _ = url.PathUnescape(rest)
	}
	return p
}

// caseInsensitiveTypes are ecosystems where package names are case-insensitive.
var caseInsensitiveTypes = map[string]bool{
	"npm": true, "pypi": true, "golang": true, "nuget": true, "gem": true,
	"deb": true, "rpm": true, "apk": true, "composer": true, "hex": true,
	"cargo": true, "github": true, "bitbucket": true, "docker": true, "oci": true,
	"generic": true, "conan": true, "cocoapods": true, "swift": true, "pub": true,
	"hackage": true, "cran": true, "huggingface": true, "mlflow": true,
}

// Normalize returns the canonical form used for comparison.
func Normalize(p PURL) PURL {
	n := p
	n.Type = strings.ToLower(strings.TrimSpace(n.Type))

	// Type aliases emitted by some tools.
	switch n.Type {
	case "go":
		n.Type = "golang"
	case "python":
		n.Type = "pypi"
	case "debian", "ubuntu":
		n.Type = "deb"
	case "alpine":
		n.Type = "apk"
	case "gomod", "go-module":
		n.Type = "golang"
	}

	if caseInsensitiveTypes[n.Type] {
		n.Namespace = strings.ToLower(n.Namespace)
		n.Name = strings.ToLower(n.Name)
	}

	switch n.Type {
	case "pypi":
		// PEP 503: runs of -, _, . are equivalent to a single -
		n.Name = pep503(n.Name)
	case "golang":
		// Syft/Trivy emit "v1.2.3"; cdxgen sometimes emits "1.2.3". Compare without the prefix.
		n.Version = strings.TrimPrefix(n.Version, "v")
		// Some tools put the whole module path in Name with empty Namespace.
		if n.Namespace == "" && strings.Contains(n.Name, "/") {
			i := strings.LastIndex(n.Name, "/")
			n.Namespace, n.Name = n.Name[:i], n.Name[i+1:]
		}
	case "npm":
		// Scoped packages: "@scope/name" may appear as namespace="@scope" or name="@scope/name".
		if n.Namespace == "" && strings.HasPrefix(n.Name, "@") && strings.Contains(n.Name, "/") {
			i := strings.Index(n.Name, "/")
			n.Namespace, n.Name = n.Name[:i], n.Name[i+1:]
		}
		n.Namespace = strings.TrimPrefix(n.Namespace, "%40")
		if n.Namespace != "" && !strings.HasPrefix(n.Namespace, "@") {
			n.Namespace = "@" + n.Namespace
		}
	case "deb", "rpm", "apk":
		// Epoch "1:" prefix is handled inconsistently; strip for comparison.
		if i := strings.Index(n.Version, ":"); i > 0 && i <= 2 {
			n.Version = n.Version[i+1:]
		}
	case "maven":
		// groupId case matters in theory; in practice tools agree. Leave as-is.
	}

	n.Version = strings.TrimSpace(n.Version)
	return n
}

func pep503(s string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return b.String()
}

// Key returns the full comparison key (with version).
func Key(p PURL) string {
	return NameKey(p) + "@" + p.Version
}

// NameKey returns the version-agnostic comparison key.
func NameKey(p PURL) string {
	if p.Namespace != "" {
		return p.Type + "/" + p.Namespace + "/" + p.Name
	}
	return p.Type + "/" + p.Name
}

// FromNameVersion builds a best-effort purl when a component has none.
func FromNameVersion(typ, name, version string) PURL {
	if typ == "" {
		typ = "unknown"
	}
	return Normalize(PURL{Type: typ, Name: name, Version: version, Qualifiers: map[string]string{}})
}

// String renders a minimal canonical purl (no qualifiers). Each namespace
// segment is percent-encoded separately, as the purl spec requires.
func String(p PURL) string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteString("/")
	if p.Namespace != "" {
		for _, seg := range strings.Split(p.Namespace, "/") {
			b.WriteString(escapeSegment(seg))
			b.WriteString("/")
		}
	}
	b.WriteString(escapeSegment(p.Name))
	if p.Version != "" {
		b.WriteString("@")
		b.WriteString(escapeSegment(p.Version))
	}
	return b.String()
}

// escapeSegment percent-encodes one purl segment. Unlike a URL path segment,
// purl requires "@" to be encoded so it cannot be mistaken for the version
// separator (npm scopes: %40babel/core).
func escapeSegment(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}

// QueryString renders the purl used for vulnerability lookups: canonical form,
// but with ecosystem conventions that databases expect restored (Go versions
// carry their "v" prefix again).
func QueryString(p PURL) string {
	q := p
	if q.Type == "golang" && q.Version != "" && !strings.HasPrefix(q.Version, "v") {
		q.Version = "v" + q.Version
	}
	return String(q)
}
