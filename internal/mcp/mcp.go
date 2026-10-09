// Package mcp discovers MCP server references in a project. No SBOM generator
// catalogues these today, so they form a shared blind spot that the comparison
// surfaces alongside the per-tool matrix.
package mcp

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

// configNames are known MCP config files (relative to any directory in the tree).
var configNames = []string{
	".mcp.json",
	"mcp.json",
	"claude_desktop_config.json",
	".cursor/mcp.json",
	".vscode/mcp.json",
	".claude/settings.json",
	".claude/settings.local.json",
	".gemini/settings.json",
	".cline/mcp.json",
	".windsurf/mcp.json",
	".continue/config.json",
}

var skipDirs = map[string]bool{"node_modules": true, ".git": true, "vendor": true, "target": true, "dist": true, "build": true, ".venv": true, "venv": true}

// Discover walks the target directory (bounded depth) and returns MCP servers.
func Discover(root string) []model.MCPServer {
	var out []model.MCPServer
	seen := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, path)
			if strings.Count(rel, string(filepath.Separator)) > 4 {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		match := false
		for _, cn := range configNames {
			if rel == cn || strings.HasSuffix(rel, string(filepath.Separator)+cn) {
				match = true
				break
			}
		}
		if !match {
			return nil
		}
		for _, s := range parseFile(path, filepath.ToSlash(rel)) {
			k := rel + "|" + s.Name
			if !seen[k] {
				seen[k] = true
				out = append(out, s)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func parseFile(path, rel string) []model.MCPServer {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	servers, _ := doc["mcpServers"].(map[string]any)
	if servers == nil {
		servers, _ = doc["servers"].(map[string]any) // VS Code
	}
	if servers == nil {
		return nil
	}
	var out []model.MCPServer
	for name, v := range servers {
		m, _ := v.(map[string]any)
		if m == nil {
			continue
		}
		s := model.MCPServer{Name: name, Source: rel}
		if c, ok := m["command"].(string); ok {
			s.Command = c
		}
		if u, ok := m["url"].(string); ok {
			s.URL = u
		}
		if args, ok := m["args"].([]any); ok {
			for _, a := range args {
				if as, ok := a.(string); ok {
					s.Args = append(s.Args, as)
				}
			}
		}
		s.Package = PackagePurl(s.Command, s.Args)
		s.Signals = localSignals(s)
		out = append(out, s)
	}
	return out
}

// PackagePurl derives the purl of the package a launcher command runs:
// "npx -y @scope/pkg@1.2" → pkg:npm/%40scope/pkg@1.2, "uvx mcp-server-x" → pkg:pypi/mcp-server-x.
// It returns "" when the command is not a known package launcher.
func PackagePurl(command string, args []string) string {
	launcher := strings.ToLower(filepath.Base(command))
	var typ string
	switch launcher {
	case "npx", "bunx", "pnpx":
		typ = "npm"
	case "uvx", "pipx":
		typ = "pypi"
	case "pnpm", "yarn":
		if len(args) == 0 || args[0] != "dlx" {
			return ""
		}
		typ, args = "npm", args[1:]
	default:
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			// Options that take a value.
			switch a {
			case "-p", "--package", "--from", "--python", "-c", "--call", "--with", "--index", "--index-url":
				i++
			}
			continue
		}
		return packageToPurl(typ, a)
	}
	return ""
}

func packageToPurl(typ, spec string) string {
	name, version := spec, ""
	if typ == "npm" {
		// A version separator is the last "@" after the first character (scopes start with "@").
		if i := strings.LastIndex(spec, "@"); i > 0 {
			name, version = spec[:i], spec[i+1:]
		}
	} else {
		// pypi: strip extras and version specifiers.
		if i := strings.IndexAny(spec, "=<>!~["); i > 0 {
			name = spec[:i]
			if strings.HasPrefix(spec[i:], "==") {
				version = strings.Trim(spec[i+2:], " ")
			}
		}
		name = strings.ToLower(name)
	}
	if name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:" + typ + "/")
	if typ == "npm" && strings.HasPrefix(name, "@") {
		scope, rest, ok := strings.Cut(name[1:], "/")
		if !ok {
			return ""
		}
		b.WriteString("%40" + url.PathEscape(scope) + "/" + url.PathEscape(rest))
	} else {
		b.WriteString(url.PathEscape(name))
	}
	if version != "" && !strings.ContainsAny(version, "^~*x><=") && version != "latest" {
		b.WriteString("@" + url.PathEscape(version))
	}
	return b.String()
}

// localSignals flags obvious risk patterns without network access.
func localSignals(s model.MCPServer) []model.Signal {
	var out []model.Signal
	joined := strings.ToLower(s.Command + " " + strings.Join(s.Args, " "))
	if s.Package != "" && !strings.Contains(s.Package[strings.LastIndex(s.Package, "/")+1:], "@") {
		if strings.HasPrefix(s.Package, "pkg:npm/") {
			out = append(out, model.Signal{Kind: "mcp", Level: "warn", Source: "local",
				Message: "unpinned npm package: the launcher resolves the latest version at every start"})
		} else if strings.HasPrefix(s.Package, "pkg:pypi/") {
			out = append(out, model.Signal{Kind: "mcp", Level: "warn", Source: "local",
				Message: "unpinned PyPI package: the launcher resolves the latest version at every start"})
		}
	}
	if strings.Contains(joined, "--dangerously") || strings.Contains(joined, "allow-all") || strings.Contains(joined, "full-access") || strings.Contains(joined, "--yolo") {
		out = append(out, model.Signal{Kind: "mcp", Level: "warn", Source: "local",
			Message: "broad permission flag in server arguments"})
	}
	if strings.HasPrefix(s.URL, "http://") && !strings.Contains(s.URL, "localhost") && !strings.Contains(s.URL, "127.0.0.1") {
		out = append(out, model.Signal{Kind: "mcp", Level: "warn", Source: "local",
			Message: "remote MCP server over plain HTTP"})
	}
	return out
}
