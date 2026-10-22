// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Ollama registry tags that the CONTROLLER staged.
//
// A placed node never reaches registry.ollama.ai (preseed.OllamaRegistryPullAllowed).
// `noo models fetch ollama:<tag>` on the controller pulls the manifest and
// blobs once, checks every blob against the sha256 the registry's manifest
// carries, and writes two files into the same flat store GGUFs live in:
//
//	ollama+<namespace>+<name>+<tag>.gguf       the model layer, verbatim
//	ollama+<namespace>+<name>+<tag>.Modelfile  FROM + the template, system
//	                                           prompt, parameters, licence
//	                                           and messages layers
//
// The node then imports a staged tag exactly as it imports any other store
// model (PullOllamaModel): both files by name, each verified against the
// gateway's artifact manifest, then `ollama create <tag> -f ...`. No new
// route, kind, mount or nginx location exists for it. What this file adds is
// the NAME mapping (it must equal the CLI's, noo-cli/src/commands/
// ollama_stage.rs; both carry the same vectors) and a stricter reading of
// the Modelfile, because a staged Modelfile is a recipe the daemon executes.
package docker

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ollamaStagePrefix starts every staged artifact name. '+' cannot occur in a
// namespace, a name or a tag, so the join is unambiguous, and it is a legal
// character in the gateway's artifact names and in a URL path segment.
const ollamaStagePrefix = "ollama+"

var (
	// A namespace has no '.', which is what tells `user/model` from a
	// host-prefixed ref (`hf.co/org/repo`) that ollama pulls from elsewhere.
	ollamaNamespaceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	ollamaNameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	ollamaTagRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
)

// OllamaStoreStem maps a registry ref to the store name its two artifacts
// share (without extension). Case-folded, `library/` and `:latest` implied.
// It refuses a ref that is not on registry.ollama.ai.
func OllamaStoreStem(ref string) (string, error) {
	r := strings.ToLower(strings.TrimSpace(ref))
	r = strings.TrimPrefix(r, "registry.ollama.ai/")
	if r == "" {
		return "", errors.New("empty model reference")
	}
	path, tag := r, "latest"
	if i := strings.LastIndex(r, ":"); i >= 0 && !strings.Contains(r[i:], "/") {
		path, tag = r[:i], r[i+1:]
	}
	ns, name := "library", path
	switch parts := strings.Split(path, "/"); len(parts) {
	case 1:
	case 2:
		ns, name = parts[0], parts[1]
	default:
		return "", fmt.Errorf("%q is not a registry.ollama.ai reference (want [namespace/]name[:tag])", ref)
	}
	if !ollamaNamespaceRe.MatchString(ns) || !ollamaNameRe.MatchString(name) || !ollamaTagRe.MatchString(tag) {
		return "", fmt.Errorf("%q is not a registry.ollama.ai reference (want [namespace/]name[:tag])", ref)
	}
	stem := ollamaStagePrefix + ns + "+" + name + "+" + tag
	if len(stem)+len(".Modelfile") >= 256 {
		return "", fmt.Errorf("%q is too long to be a store artifact name", ref)
	}
	return stem, nil
}

// stagedHeader is what a staged Modelfile says about itself.
type stagedHeader struct {
	// ModelSHA256 is the digest the registry's manifest gave the model layer.
	ModelSHA256 string
}

var (
	stagedMarkerRe = regexp.MustCompile(`(?m)^# noo-ollama-stage: v1$`)
	stagedShaRe    = regexp.MustCompile(`(?m)^# model-sha256: ([0-9a-f]{64})$`)
)

// stagedModelfileDirectives are the only directives a staged Modelfile may
// use: the layers an ollama manifest carries, which `ollama create` rebuilds.
// ADAPTER, and anything that names another file, are absent on purpose.
var stagedModelfileDirectives = map[string]bool{
	"FROM": true, "TEMPLATE": true, "SYSTEM": true, "PARAMETER": true,
	"LICENSE": true, "MESSAGE": true, "RENDERER": true, "PARSER": true,
}

// checkStagedModelfile reads a staged Modelfile as the node will hand it to
// ollama: the marker and the model digest must be there, FROM must be exactly
// the staged weight, and no directive outside the allow-list may appear.
// Quoted ("""...""") blocks are text, not directives.
func checkStagedModelfile(body, stem string) (*stagedHeader, error) {
	if !stagedMarkerRe.MatchString(body) {
		return nil, fmt.Errorf("%s.Modelfile in the store is not a staged ollama model (no `# noo-ollama-stage: v1` header) — restage it with `noo models fetch ollama:<tag> --force`", stem)
	}
	m := stagedShaRe.FindStringSubmatch(body)
	if m == nil {
		return nil, fmt.Errorf("%s.Modelfile carries no `# model-sha256:` line — restage it with `noo models fetch ollama:<tag> --force`", stem)
	}
	froms := 0
	inBlock := false
	for _, line := range strings.Split(body, "\n") {
		if inBlock {
			if strings.Contains(line, `"""`) {
				inBlock = false
			}
			continue
		}
		t := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		word := strings.ToUpper(fields[0])
		if !stagedModelfileDirectives[word] {
			return nil, fmt.Errorf("%s.Modelfile uses %q, which a staged ollama model may not (allowed: FROM TEMPLATE SYSTEM PARAMETER LICENSE MESSAGE RENDERER PARSER)", stem, fields[0])
		}
		rest := strings.TrimSpace(t[len(fields[0]):])
		if word == "FROM" {
			froms++
			if strings.Trim(rest, `"'`) != "./"+stem+".gguf" {
				return nil, fmt.Errorf("%s.Modelfile FROM names %q, not ./%s.gguf", stem, rest, stem)
			}
		}
		if i := strings.Index(rest, `"""`); i >= 0 && !strings.Contains(rest[i+3:], `"""`) {
			inBlock = true
		}
	}
	if inBlock {
		return nil, fmt.Errorf("%s.Modelfile has an unterminated \"\"\" block", stem)
	}
	if froms != 1 {
		return nil, fmt.Errorf("%s.Modelfile has %d FROM lines, want exactly 1", stem, froms)
	}
	return &stagedHeader{ModelSHA256: m[1]}, nil
}
