// Package ui serves the embedded single-page viewer on localhost.
package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/junseok-seo/sbomcmp/internal/model"
)

//go:embed static/*
var static embed.FS

// Serve starts an HTTP server for one result and blocks. If port is 0 a free
// port is chosen. If open is true the system browser is launched.
func Serve(res *model.Result, resultPath string, port int, open bool) error {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/result", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		// Re-read from disk each time so a re-scan shows up on refresh.
		if resultPath != "" {
			if data, err := os.ReadFile(resultPath); err == nil {
				w.Write(data)
				return
			}
		}
		json.NewEncoder(w).Encode(res)
	})
	mux.HandleFunc("/api/raw/", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[len("/api/raw/"):]
		for _, g := range res.Generators {
			if g.Name == name && g.RawPath != "" {
				http.ServeFile(w, r, g.RawPath)
				return
			}
		}
		http.NotFound(w, r)
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	url := "http://" + ln.Addr().String()
	fmt.Fprintf(os.Stderr, "sbomcmp ui: %s  (Ctrl-C to stop)\n", url)
	if open {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}()
	}
	return http.Serve(ln, mux)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
