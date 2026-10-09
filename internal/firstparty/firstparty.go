// Package firstparty finds the packages a scanned tree declares itself —
// the names in its own package.json, Cargo.toml, pyproject.toml and go.mod
// files — so that registry checks can tell "a dependency we pull" from "a
// package we are". A first-party name that does not exist on a public
// registry is normal; the same observation about a dependency is
// slopsquatting.
package firstparty

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/junseok-seo/sbomcmp/internal/model"
	"github.com/junseok-seo/sbomcmp/internal/purl"
)

// Decl is one package declared by the project.
type Decl struct {
	NameKey string `json:"nameKey"`           // type/namespace/name, normalized like rows
	Version string `json:"version,omitempty"` // declared version ("" when the manifest has none)
	Source  string `json:"source"`            // manifest path relative to the root, or "<tool> metadata.component"
	Private bool   `json:"private,omitempty"`
}

var skipDirs = map[string]bool{"node_modules": true, ".git": true, "vendor": true, "target": true, "dist": true, "build": true, ".venv": true, "venv": true, "__pycache__": true}

// Collect walks root (bounded depth) and returns every package declaration.
func Collect(root string) []Decl {
	var out []Decl
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if skipDirs[d.Name()] || strings.Count(rel, string(filepath.Separator)) > 6 {
				return filepath.SkipDir
			}
			return nil
		}
		rel = filepath.ToSlash(rel)
		switch d.Name() {
		case "package.json":
			out = append(out, packageJSON(path, rel)...)
		case "package-lock.json":
			out = append(out, packageLock(path, rel)...)
		case "Cargo.toml":
			out = append(out, cargoToml(path, rel)...)
		case "pyproject.toml":
			out = append(out, pyproject(path, rel)...)
		case "go.mod":
			out = append(out, goMod(path, rel)...)
		}
		return nil
	})
	return out
}

// FromRoot converts a generator's metadata.component into a declaration.
func FromRoot(tool string, c *model.Component) *Decl {
	if c == nil || c.NameKey == "" || c.Type == "unknown" {
		return nil
	}
	return &Decl{NameKey: c.NameKey, Version: c.Version, Source: tool + " metadata.component"}
}

// Mark flags rows that are first-party. A row matches a declaration when the
// name key is equal and either the declaration has no version or the
// versions agree — so a registry dependency that merely shares a name with
// an internal package at another version is still checked. A name-only
// match is recorded as a candidate; the registry check settles it (see
// Confirm).
func Mark(rows []model.Row, decls []Decl) int {
	if len(decls) == 0 {
		return 0
	}
	byKey := map[string][]Decl{}
	for _, d := range decls {
		byKey[d.NameKey] = append(byKey[d.NameKey], d)
	}
	n := 0
	for i := range rows {
		for _, d := range byKey[rows[i].NameKey] {
			if d.Version == "" || strings.TrimPrefix(d.Version, "v") == strings.TrimPrefix(rows[i].Version, "v") {
				rows[i].FirstParty = true
				rows[i].FirstPartySource = d.Source
				rows[i].FirstPartyCandidate = ""
				n++
				break
			}
			if rows[i].FirstPartyCandidate == "" {
				rows[i].FirstPartyCandidate = d.Source
			}
		}
	}
	return n
}

// Confirm settles a name-only candidate once a registry has answered: a
// name the registry does not know, declared by this project, is the
// project's own package at a version the manifest no longer states (a stale
// lockfile root, for instance). Any slopsquat signal on it is dropped.
// Returns true when the row was promoted.
func Confirm(row *model.Row, registryMissing bool) bool {
	if row.FirstPartyCandidate == "" || row.FirstParty || !registryMissing {
		return false
	}
	row.FirstParty = true
	row.FirstPartySource = row.FirstPartyCandidate + " (version differs from manifest)"
	row.FirstPartyCandidate = ""
	kept := row.Signals[:0]
	for _, s := range row.Signals {
		if s.Kind != "slopsquat" {
			kept = append(kept, s)
		}
	}
	row.Signals = kept
	return true
}

func key(typ, name, version string) (string, string) {
	p := purl.Normalize(purl.PURL{Type: typ, Name: name, Version: version, Qualifiers: map[string]string{}})
	return purl.NameKey(p), p.Version
}

func packageJSON(path, rel string) []Decl {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Private bool   `json:"private"`
	}
	if json.Unmarshal(data, &doc) != nil || doc.Name == "" {
		return nil
	}
	nk, v := key("npm", doc.Name, doc.Version)
	return []Decl{{NameKey: nk, Version: v, Source: rel, Private: doc.Private}}
}

// packageLock reads the root entry of an npm lockfile: it names the project
// itself, and its version can lag behind package.json.
func packageLock(path, rel string) []Decl {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	name, version := doc.Name, doc.Version
	if root, ok := doc.Packages[""]; ok {
		if root.Name != "" {
			name = root.Name
		}
		if root.Version != "" {
			version = root.Version
		}
	}
	if name == "" {
		return nil
	}
	nk, v := key("npm", name, version)
	return []Decl{{NameKey: nk, Version: v, Source: rel}}
}

var (
	tomlSection = regexp.MustCompile(`(?m)^\s*\[([^\]]+)\]\s*$`)
	tomlKV      = regexp.MustCompile(`(?m)^\s*([A-Za-z_-]+)\s*=\s*"([^"]*)"`)
)

// tomlTable returns the string key/values of one top-level table.
func tomlTable(data, table string) map[string]string {
	locs := tomlSection.FindAllStringSubmatchIndex(data, -1)
	for i, loc := range locs {
		if strings.TrimSpace(data[loc[2]:loc[3]]) != table {
			continue
		}
		end := len(data)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out := map[string]string{}
		for _, kv := range tomlKV.FindAllStringSubmatch(data[loc[1]:end], -1) {
			out[kv[1]] = kv[2]
		}
		return out
	}
	return nil
}

func cargoToml(path, rel string) []Decl {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pkg := tomlTable(string(data), "package")
	if pkg == nil || pkg["name"] == "" {
		return nil
	}
	nk, v := key("cargo", pkg["name"], pkg["version"])
	return []Decl{{NameKey: nk, Version: v, Source: rel}}
}

func pyproject(path, rel string) []Decl {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := string(data)
	tbl := tomlTable(s, "project")
	if tbl == nil || tbl["name"] == "" {
		tbl = tomlTable(s, "tool.poetry")
	}
	if tbl == nil || tbl["name"] == "" {
		return nil
	}
	nk, v := key("pypi", tbl["name"], tbl["version"])
	return []Decl{{NameKey: nk, Version: v, Source: rel}}
}

var goModule = regexp.MustCompile(`(?m)^module\s+(\S+)`)

func goMod(path, rel string) []Decl {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	m := goModule.FindSubmatch(data)
	if m == nil {
		return nil
	}
	nk, _ := key("golang", strings.Trim(string(m[1]), `"`), "")
	return []Decl{{NameKey: nk, Source: rel}}
}
