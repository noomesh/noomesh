// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeSecret(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecretPrecedenceFileThenPrefixThenPlain(t *testing.T) {
	f := writeSecret(t, "from-file\n")
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"file wins over prefix", map[string]string{"NOO_CLUSTER_SECRET_FILE": f, "NOO_SECRET_NOO_CLUSTER_SECRET": "pref"}, "from-file"},
		{"prefix wins over plain", map[string]string{"NOO_SECRET_NOO_CLUSTER_SECRET": "pref", "NOO_CLUSTER_SECRET": "plain"}, "pref"},
		{"plain alone", map[string]string{"NOO_CLUSTER_SECRET": "plain"}, "plain"},
		{"empty file pointer is unset", map[string]string{"NOO_CLUSTER_SECRET_FILE": "", "NOO_CLUSTER_SECRET": "plain"}, "plain"},
		{"nothing", map[string]string{}, ""},
	}
	for _, c := range cases {
		got, err := SecretFrom("NOO_CLUSTER_SECRET", envMap(c.env))
		if err != nil {
			t.Fatalf("%s: unexpected error %v", c.name, err)
		}
		if got != c.want {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestSecretRefusesBothPlainAndFile(t *testing.T) {
	f := writeSecret(t, "from-file")
	_, err := SecretFrom("NATS_NODE_PASSWORD", envMap(map[string]string{
		"NATS_NODE_PASSWORD_FILE": f, "NATS_NODE_PASSWORD": "plain",
	}))
	if err == nil || !strings.Contains(err.Error(), "both NATS_NODE_PASSWORD and NATS_NODE_PASSWORD_FILE") {
		t.Fatalf("want a both-set refusal, got %v", err)
	}
}

func TestSecretEmptyFileIsAnErrorNotUnset(t *testing.T) {
	for _, body := range []string{"", "\n", "\r\n"} {
		f := writeSecret(t, body)
		_, err := SecretFrom("NOO_NODE_AGENT_TOKEN", envMap(map[string]string{
			"NOO_NODE_AGENT_TOKEN_FILE": f, "NOO_SECRET_NOO_NODE_AGENT_TOKEN": "must-not-be-used",
		}))
		if err == nil || !strings.Contains(err.Error(), "empty") || !strings.Contains(err.Error(), f) {
			t.Fatalf("body %q: want an empty-file error naming %s, got %v", body, f, err)
		}
	}
}

func TestSecretUnreadableFileNeverFallsThrough(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	v, err := SecretFrom("NOO_CLUSTER_SECRET", envMap(map[string]string{
		"NOO_CLUSTER_SECRET_FILE":       missing,
		"NOO_SECRET_NOO_CLUSTER_SECRET": "fallback-must-not-be-used",
	}))
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("want an unreadable-file error naming the path, got %q, %v", v, err)
	}
	if v != "" {
		t.Fatalf("an unreadable file must not answer a value, got %q", v)
	}
}

func TestStripExactlyOneNewline(t *testing.T) {
	cases := map[string]string{
		"abc":       "abc",
		"abc\n":     "abc",
		"abc\r\n":   "abc",
		"abc\n\n":   "abc\n",
		"abc \n":    "abc ",
		"a\nb\n":    "a\nb",
		"abc\r\n\n": "abc\r\n",
	}
	for in, want := range cases {
		if got := StripOneNewline(in); got != want {
			t.Fatalf("StripOneNewline(%q) = %q, want %q", in, got, want)
		}
	}
	f := writeSecret(t, "s3cret\n\n")
	got, err := SecretFrom("NATS_NODE_PASSWORD", envMap(map[string]string{"NATS_NODE_PASSWORD_FILE": f}))
	if err != nil || got != "s3cret\n" {
		t.Fatalf("file read must strip ONE newline: got %q, %v", got, err)
	}
}

func TestCheckSecretsNamesEveryFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	f := writeSecret(t, "x")
	err := CheckSecrets(envMap(map[string]string{
		"NOO_CLUSTER_SECRET_FILE": missing,
		"NATS_NODE_PASSWORD_FILE": f, "NATS_NODE_PASSWORD": "plain",
		"NOO_NODE_AGENT_TOKEN": "fine",
	}))
	if err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "both NATS_NODE_PASSWORD") {
		t.Fatalf("want both failures named, got %v", err)
	}
	if err := CheckSecrets(envMap(map[string]string{"NOO_CLUSTER_SECRET": "plain"})); err != nil {
		t.Fatalf("an old plain env must still boot: %v", err)
	}
}

func TestSecretLookupOverlaysOnlyManifestNames(t *testing.T) {
	f := writeSecret(t, "pw\n")
	get, err := SecretLookup(envMap(map[string]string{
		"NATS_NODE_USER": "node-x", "NATS_NODE_PASSWORD_FILE": f,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if get("NATS_NODE_PASSWORD") != "pw" || get("NATS_NODE_USER") != "node-x" {
		t.Fatalf("lookup: password %q user %q", get("NATS_NODE_PASSWORD"), get("NATS_NODE_USER"))
	}
	if _, err := SecretLookup(envMap(map[string]string{"NATS_NODE_PASSWORD_FILE": filepath.Join(t.TempDir(), "absent")})); err == nil {
		t.Fatal("an unreadable NATS password file must be an error, not an anonymous connect")
	}
}

func TestLoadReadsTheAuthPairThroughTheFile(t *testing.T) {
	f := writeSecret(t, "tok\n")
	t.Setenv("NOO_NODE_AGENT_TOKEN_FILE", f)
	t.Setenv("NOO_NODE_AGENT_TOKEN", "")
	t.Setenv("NOO_CLUSTER_SECRET", "plain-cluster")
	c := Load()
	if c.NodeAgentToken != "tok" || c.ClusterSecret != "plain-cluster" {
		t.Fatalf("Load: token %q secret %q", c.NodeAgentToken, c.ClusterSecret)
	}
}
