package mcp

import (
	"path/filepath"
	"testing"
)

func TestPackagePurl(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		want string
	}{
		{"npx", []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, "pkg:npm/%40modelcontextprotocol/server-filesystem"},
		{"npx", []string{"-y", "github-mcp-server@1.2.0"}, "pkg:npm/github-mcp-server@1.2.0"},
		{"npx", []string{"--yes", "-p", "foo", "bar"}, "pkg:npm/bar"},
		{"/usr/local/bin/uvx", []string{"mcp-server-browser", "--dangerously-allow-all"}, "pkg:pypi/mcp-server-browser"},
		{"uvx", []string{"--from", "git+https://x", "mcp-Server-Git==1.0"}, "pkg:pypi/mcp-server-git@1.0"},
		{"pnpm", []string{"dlx", "@scope/x"}, "pkg:npm/%40scope/x"},
		{"docker", []string{"run", "-i", "ghcr.io/x"}, ""},
		{"node", []string{"server.js"}, ""},
	}
	for _, c := range cases {
		if got := PackagePurl(c.cmd, c.args); got != c.want {
			t.Errorf("%s %v: got %q want %q", c.cmd, c.args, got, c.want)
		}
	}
}

func TestDiscoverSampleProject(t *testing.T) {
	servers := Discover(filepath.Join("..", "..", "testdata", "sample-project"))
	if len(servers) != 4 {
		t.Fatalf("expected 4 servers, got %d: %+v", len(servers), servers)
	}
	byName := map[string]int{}
	for i, s := range servers {
		byName[s.Name] = i
	}
	fs := servers[byName["filesystem"]]
	if fs.Package != "pkg:npm/%40modelcontextprotocol/server-filesystem" || len(fs.Signals) != 1 {
		t.Fatalf("filesystem: %+v", fs)
	}
	br := servers[byName["browser"]]
	if br.Package != "pkg:pypi/mcp-server-browser" || len(br.Signals) != 2 || br.Source != ".cursor/mcp.json" {
		t.Fatalf("browser: %+v", br)
	}
	it := servers[byName["internal-tools"]]
	if it.Package != "" || len(it.Signals) != 1 {
		t.Fatalf("internal-tools: %+v", it)
	}
}
