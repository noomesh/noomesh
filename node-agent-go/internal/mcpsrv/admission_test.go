// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The exfiltration hole: cmd.Env = os.Environ() handed every stdio MCP
// server the agent's whole environment — NOO_CLUSTER_SECRET,
// NOO_NODE_AGENT_TOKEN, NATS_PASSWORD — as a user in the docker group.
func TestScrubbedEnvCarriesNoAgentSecrets(t *testing.T) {
	t.Setenv("NOO_CLUSTER_SECRET", "fleet-secret-value")
	t.Setenv("NOO_NODE_AGENT_TOKEN", "node-token-value")
	t.Setenv("NATS_PASSWORD", "nats-password-value")
	t.Setenv("PATH", "/usr/bin:/bin")

	env := ScrubbedEnv(map[string]string{"GITHUB_TOKEN": "from-the-node-secrets-file"}, false)
	joined := strings.Join(env, "\n")

	for _, leaked := range []string{"fleet-secret-value", "node-token-value", "nats-password-value",
		"NOO_CLUSTER_SECRET", "NOO_NODE_AGENT_TOKEN", "NATS_PASSWORD"} {
		if strings.Contains(joined, leaked) {
			t.Errorf("scrubbed env leaked %q:\n%s", leaked, joined)
		}
	}
	if !strings.Contains(joined, "PATH=/usr/bin:/bin") {
		t.Errorf("PATH must be inherited so the command resolves:\n%s", joined)
	}
	if !strings.Contains(joined, "GITHUB_TOKEN=from-the-node-secrets-file") {
		t.Errorf("the placement's own resolved values must be present:\n%s", joined)
	}

	// The contained form drops what the IMAGE supplies. The agent's PATH
	// describes the agent's filesystem, and injecting it into a container
	// overrides the image's own with directories that are not in it.
	contained := strings.Join(ScrubbedEnv(map[string]string{"GITHUB_TOKEN": "x"}, true), "\n")
	if strings.Contains(contained, "PATH=") || strings.Contains(contained, "HOME=") {
		t.Errorf("a contained server must not inherit the agent's PATH/HOME:\n%s", contained)
	}
	if !strings.Contains(contained, "GITHUB_TOKEN=x") {
		t.Errorf("the placement's own values are still passed:\n%s", contained)
	}
	for _, leaked := range []string{"fleet-secret-value", "node-token-value", "nats-password-value"} {
		if strings.Contains(contained, leaked) {
			t.Errorf("contained env leaked %q:\n%s", leaked, contained)
		}
	}
}

// The sibling hole, no exec required: ResolveRefs used to resolve $NAME from
// the process environment, so a streamable_http placement with
// headers:{"X":"$NOO_CLUSTER_SECRET"} POSTed the fleet secret to any URL.
func TestSecretRefsResolveOnlyFromTheNodeLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-secrets.env")
	if err := os.WriteFile(path, []byte("# node-local\nGITHUB_TOKEN=ghp_from_file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SecretsFileEnv, path)
	t.Setenv("NOO_CLUSTER_SECRET", "fleet-secret-value")
	ResetSecretsCache()
	t.Cleanup(ResetSecretsCache)

	got, err := ResolveRefs(map[string]string{"X": "$GITHUB_TOKEN"}, SecretLookup)
	if err != nil {
		t.Fatalf("a name in the node's own secrets file must resolve: %v", err)
	}
	if got["X"] != "ghp_from_file" {
		t.Errorf("got %v", got)
	}

	// The fleet secret is in this process's environment and must stay
	// unreachable from a placement.
	if _, err := ResolveRefs(map[string]string{"X": "$NOO_CLUSTER_SECRET"}, SecretLookup); err == nil {
		t.Fatal("a placement must not be able to name the agent's own environment")
	}
}
