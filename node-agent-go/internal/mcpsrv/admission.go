// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"sync"
)

// The environment a node-local MCP server gets, and where its secrets
// come from.
//
// The command allow-list that used to live here is gone, and so is
// NOO_MCP_STDIO_ALLOW. It bounded WHICH binary a controller-supplied stdio
// placement could run, but left the controller choosing that binary's
// args, cwd and environment — and an allow-listed interpreter with
// attacker-chosen arguments is the same hole wearing a hat (`uvx`, `npx`,
// `python` and `node` are exactly what an operator would allow-list for
// MCP, and each runs arbitrary code from its argv). The controller no
// longer supplies stdio servers at all; see local.go.
//
// What remains here is the other half of that decision:
//
//   - a server started by this agent gets a BUILT environment — PATH, HOME,
//     LANG, LC_ALL, TZ and its own declared values — never os.Environ(),
//     which on every node holds NOO_CLUSTER_SECRET, NOO_NODE_AGENT_TOKEN
//     and its NATS_NODE_PASSWORD;
//   - a `$NAME` reference resolves against a node-local, operator-written
//     secrets file, never the agent's environment. The registry is designed
//     to hold references rather than secrets precisely so the NODE decides
//     what a reference means; resolving against the agent's own environment
//     handed that decision back, and let a streamable_http placement with
//     `headers: {"X-Api-Key": "$NOO_CLUSTER_SECRET"}` post the fleet secret
//     to any URL it named.

// SecretsFileEnv points at the node-local file MCP `$NAME` references
// resolve against. Default mcpSecretsDefaultPath.
//
// A SEPARATE file from /etc/noo-node-agent.env on purpose. The agent env
// holds the fleet credentials; if references resolved there, a placement
// could name one. This file holds only what an operator deliberately put in
// it for MCP servers to use.
const SecretsFileEnv = "NOO_MCP_SECRETS_FILE"

const mcpSecretsDefaultPath = "/etc/noo/mcp-secrets.env"

// baseEnvKeys are the ONLY variables inherited from the agent's process
// environment. Everything a server needs beyond these comes from its own
// placement spec, resolved against the node-local secrets file.
//
// Deliberately absent: NOO_*, NATS_*, DOCKER_HOST, AWS_*, and every other
// credential the agent happens to hold. A child process that inherits its
// parent's secrets has the parent's reach.
var baseEnvKeys = []string{"PATH", "HOME", "LANG", "LC_ALL", "TZ"}

// containerSuppliedKeys are the base keys a CONTAINER supplies itself. The
// agent's own PATH and HOME describe the agent's filesystem, not the image's,
// and passing them in would override the image's own values with paths that do
// not exist inside it. The rest of baseEnvKeys (locale, timezone) still
// describe the machine and are still worth carrying across.
var containerSuppliedKeys = map[string]bool{"PATH": true, "HOME": true}

// ScrubbedEnv builds the environment for a node-local MCP server: the small
// inherited base, plus the placement's own resolved values.
//
// `contained` drops the keys a container image supplies for itself. It is a
// parameter rather than a second function so there is exactly ONE declaration
// of what an MCP server may inherit from the agent, and one test watching it.
func ScrubbedEnv(resolved map[string]string, contained bool) []string {
	out := make([]string, 0, len(baseEnvKeys)+len(resolved))
	for _, k := range baseEnvKeys {
		if contained && containerSuppliedKeys[k] {
			continue
		}
		if v, ok := os.LookupEnv(k); ok && v != "" {
			out = append(out, k+"="+v)
		}
	}
	keys := make([]string, 0, len(resolved))
	for k := range resolved {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+resolved[k])
	}
	return out
}

var (
	secretsOnce sync.Once
	secretsMap  map[string]string
	secretsErr  error
)

// secretsPath is the node-local MCP secrets file in effect.
func secretsPath() string {
	if v := strings.TrimSpace(os.Getenv(SecretsFileEnv)); v != "" {
		return v
	}
	return mcpSecretsDefaultPath
}

// SecretLookup is the resolver ResolveRefs uses: a node-local,
// operator-written dotenv file, and NOTHING else.
//
// A missing file is not an error here — it means "this node was given no MCP
// secrets", and a placement that needs one then fails with ResolveRefs's own
// "unresolved secret reference" message, which names what is missing. That
// is a better failure than resolving the name against the agent's env and
// shipping the fleet secret to whatever URL the placement named.
func SecretLookup(name string) (string, bool) {
	secretsOnce.Do(func() { secretsMap, secretsErr = readSecretsFile(secretsPath()) })
	if secretsErr != nil {
		return "", false
	}
	v, ok := secretsMap[name]
	return v, ok
}

// ResetSecretsCache re-reads the secrets file on the next lookup. Tests only.
func ResetSecretsCache() { secretsOnce = sync.Once{} }

// readSecretsFile parses a minimal dotenv: KEY=VALUE lines, '#' comments,
// blank lines. No expansion, no `export`, no quotes stripped beyond one
// matching pair — this file is read by a Go program, not by a shell, and
// pretending otherwise is how a parser grows a code path.
func readSecretsFile(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // operator-declared path
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if k != "" {
			out[k] = v
		}
	}
	return out, sc.Err()
}
