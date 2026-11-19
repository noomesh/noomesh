// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package containerdial

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// backendDialSites are the functions that build a transport which dials a
// backend by its docker-DNS name (a door, a noo-* container, OLLAMA_URL).
// Each must route it through ApplyDial (withBackendDial in internal/api is
// ApplyDial's one wrapper). Paths are relative to node-agent-go.
var backendDialSites = map[string][]string{
	"internal/agent/agent.go":                 {"New"},
	"internal/api/inference_proxy.go":         {"withBackendDial", "httpsTransportWithFirstByte", "backendClient"},
	"internal/docker/ollama_mirror_import.go": {"ollamaTransport"},
	"internal/backendrt/native.go":            {"laneTransport"},
}

// controllerOnly are transport builders in backend-referencing files that
// dial only the controller / model cache (never a docker name), so the
// host-mode dialer must NOT be forced on them. Empty today.
var controllerOnly = map[string]bool{}

const nodeAgentRoot = "../.."

// fnInfo counts, per function, the transports it builds and the times it
// applies the dialer. Counted, not just seen: ollamaTransport builds one per
// branch, and a dialer on one branch must not hide its absence on the other.
type fnInfo struct {
	builds  int // config.HTTPTransport() or http.Transport{...}
	applies int // ApplyDial(...) or withBackendDial(...)
}

func (i fnInfo) uncovered() bool { return i.builds > i.applies }

func scanFile(t *testing.T, path string) (fns map[string]fnInfo, dialsBackend bool) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0) // comments dropped
	if err != nil {
		t.Fatal(err)
	}
	fns = map[string]fnInfo{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == "BackendDialURL" {
				dialsBackend = true
			}
		case *ast.BasicLit:
			if strings.Contains(x.Value, "OLLAMA_URL") {
				dialsBackend = true
			}
		}
		return true
	})
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		var info fnInfo
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				switch fn := x.Fun.(type) {
				case *ast.SelectorExpr:
					switch fn.Sel.Name {
					case "HTTPTransport":
						info.builds++
					case "ApplyDial":
						info.applies++
					}
				case *ast.Ident:
					if fn.Name == "withBackendDial" || fn.Name == "ApplyDial" {
						info.applies++
					}
				}
			case *ast.CompositeLit:
				if sel, ok := x.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Transport" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "http" {
						info.builds++
					}
				}
			}
			return true
		})
		fns[fd.Name.Name] = info
	}
	return fns, dialsBackend
}

// A transport the agent builds for itself does not inherit
// http.DefaultTransport's host-mode dialer. The Ollama store import built
// one (config.HTTPTransport / &http.Transport{}) and dialled the managed
// container's door through the system resolver on every host-mode node.
// Two checks: the listed sites apply the dialer, and any OTHER function
// that builds a transport in a file that dials a backend URL does too.
func TestBackendTransportsApplyTheHostDial(t *testing.T) {
	if len(backendDialSites) == 0 {
		t.Fatal("backendDialSites is empty: the guard checks nothing")
	}
	for file, fnames := range backendDialSites {
		fns, _ := scanFile(t, filepath.Join(nodeAgentRoot, file))
		for _, name := range fnames {
			info, ok := fns[name]
			if !ok {
				t.Errorf("%s: function %s not found — update backendDialSites", file, name)
				continue
			}
			if info.applies == 0 || info.uncovered() {
				t.Errorf("%s: %s dials a backend by its docker-DNS name but builds %d transport(s) and calls containerdial.ApplyDial %d time(s) — a host-mode agent cannot resolve the name on the uncovered one", file, name, info.builds, info.applies)
			}
		}
	}

	var offenders []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(nodeAgentRoot, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			fns, dialsBackend := scanFile(t, p)
			if !dialsBackend {
				return nil
			}
			rel, _ := filepath.Rel(nodeAgentRoot, p)
			rel = filepath.ToSlash(rel)
			for name, info := range fns {
				if info.uncovered() && !controllerOnly[rel+":"+name] {
					offenders = append(offenders, rel+": "+name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s builds an *http.Transport in a file that dials a backend URL (BackendDialURL / OLLAMA_URL) without containerdial.ApplyDial — route it through ApplyDial, or list it in controllerOnly with the reason it never dials a docker name", o)
	}
}
