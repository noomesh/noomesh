// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Command node-agent runs the PAI cluster node agent.
//
// This is a drop-in replacement for the Python docker/node_agent.py.
// It registers with the gateway controller, sends heartbeats, manages
// Docker backend containers, and subscribes to NATS job dispatches.
//
// Configuration is entirely via environment variables — see internal/config.
// Arguments are parsed in cli.go: none starts the agent; --version and
// --help print and exit without reading anything; any other argument exits 2.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/noomesh/noomesh/node-agent-go/internal/api"
	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
	"github.com/noomesh/noomesh/node-agent-go/internal/logring"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/agent"
	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlenv"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

func main() {
	// Arguments first, and --version/--help/unknown exit HERE — before any
	// environment read, log setup, file or listener. Only an empty argument
	// list reaches the agent (see cli.go).
	cmd, msg := parseArgs(os.Args[1:])
	if code, done := earlyExit(cmd, msg, os.Stdout, os.Stderr); done {
		os.Exit(code)
	}

	// Preseed mode: `noo-node-agent -preseed <repo-url> <dest-dir>`
	// Copies a HuggingFace model from the controller's model-weight store
	// (nginx JSON autoindex at …/hf/models--org--name/) into <dest-dir>,
	// taking only refs/main + the one snapshot main points at — HF loads
	// offline from that and it avoids the ~4x over-fetch a blind mirror hits
	// on multi-snapshot repos. Run inside a disposable helper container (this
	// same image) with the node's HF cache bind-mounted — no wget/curl/rsync
	// needed. Prints the file count; exits non-zero on error so the caller
	// falls back to a normal HF download.
	if cmd == cmdPreseed {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		n, err := preseed.New().MirrorHFRepo(ctx, os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, "preseed error:", err)
			os.Exit(1)
		}
		fmt.Printf("preseed ok: %d files\n", n)
		os.Exit(0)
	}

	// Single-file preseed: `noo-node-agent -preseed-file <url> <dest>`
	// Copies one file (a GGUF weight) from the controller's model-weight store
	// (/gguf/<name>) into <dest>, skipping if already present at the same size.
	// Runs inside a disposable helper with the node's models dir bind-mounted.
	// Optional 4th arg: the sha256 the controller's artifact manifest stated
	// With it, the bytes are verified while streaming
	// and a mismatch fails without touching <dest>; without it, behaviour is
	// unchanged (size-shortcut opportunistic caching).
	if cmd == cmdPreseedFile {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		var wrote bool
		var err error
		if len(os.Args) >= 5 && os.Args[4] != "" {
			wrote, err = preseed.New().FetchOneVerified(ctx, os.Args[2], os.Args[3], os.Args[4])
		} else {
			wrote, err = preseed.New().FetchOne(ctx, os.Args[2], os.Args[3])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "preseed-file error:", err)
			os.Exit(1)
		}
		fmt.Printf("preseed-file ok: wrote=%v\n", wrote)
		os.Exit(0)
	}

	// Built-in healthcheck mode: `noo-node-agent -healthcheck`
	// Used by Docker HEALTHCHECK without needing curl in the image.
	// Always HTTPS — PAI cluster does not support plain HTTP.
	if cmd == cmdHealthcheck {
		// VERIFIED against the cluster CA. This used to set
		// InsecureSkipVerify, which made the healthcheck unable to tell its
		// own agent from anything else listening on the port — and the agent
		// env file always carries NOO_TLS_CA (deploy/noo-node-agent.env.tmpl),
		// so there was an anchor available the whole time. The agent's own
		// cert names `localhost` among its DNS SANs (pki::issue_node_cert),
		// so the loopback probe verifies. No CA, no verdict: exit non-zero
		// rather than report healthy on an unidentified peer.
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		// Anchor: the cluster CA when the env names one; otherwise the
		// agent's OWN certificate, pinned as its own root. The second is
		// still verification — Go accepts a leaf that is itself in the root
		// pool — so an agent deployed without NOO_TLS_CA checks that the
		// thing on its port presents exactly the certificate it serves,
		// instead of accepting anything at all.
		anchor, anchorFrom := ctrlenv.TLSCA(), "NOO_TLS_CA"
		if anchor == "" {
			anchor, anchorFrom = ctrlenv.TLSCert(), "NOO_TLS_CERT (self-pinned)"
		}
		if anchor == "" {
			fmt.Fprintln(os.Stderr, "healthcheck: neither NOO_TLS_CA nor NOO_TLS_CERT is set — nothing to verify the agent's TLS certificate against")
			os.Exit(1)
		}
		caPEM, err := os.ReadFile(anchor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck: cannot read %s (%s): %v\n", anchorFrom, anchor, err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			fmt.Fprintf(os.Stderr, "healthcheck: %s (%s) contains no usable certificate\n", anchorFrom, anchor)
			os.Exit(1)
		}
		tlsCfg.RootCAs = pool
		// When mTLS is enabled the agent's own server cert doubles as its
		// client cert — it satisfies its own CA, so it can talk to itself.
		certPath := ctrlenv.TLSCert()
		keyPath := ctrlenv.TLSKey()
		if certPath != "" && keyPath != "" {
			if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
				tlsCfg.Certificates = []tls.Certificate{cert}
			}
		}
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
		// Must follow NODE_AGENT_PORT: a second agent on another port would
		// otherwise probe the FIRST agent's port and report itself healthy
		// while being dead — or unhealthy while being fine.
		hcPort := 8081
		if v := os.Getenv("NODE_AGENT_PORT"); v != "" {
			if p, err := strconv.Atoi(v); err == nil && p > 0 {
				hcPort = p
			}
		}
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/health", hcPort))
		if err != nil || resp.StatusCode != 200 {
			fmt.Fprintln(os.Stderr, "unhealthy")
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
			}
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Structured logging to match the Python structlog output style
	// Every record goes to stdout (the journal) AND to an in-memory ring
	// the API serves as the agent's own log (`noo cluster logs <node>`).
	handler := logring.NewTee(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}),
		slog.NewJSONHandler(api.OwnLog, &slog.HandlerOptions{Level: logLevel()}),
	)
	slog.SetDefault(slog.New(handler))
	imagesource.LogRetired()

	// A retired certificate-organization override is a refusal, not a
	// silently ignored knob: an operator who set one believes it widens or
	// renames who counts as the controller, and it no longer does.
	if msg := auth.RetiredOrgOverrideRefusal(os.Getenv); msg != "" {
		slog.Error("refusing to start", "reason", msg)
		os.Exit(2)
	}

	// An undeclared node keeps the root it already runs on (a legacy
	// default) instead of moving to today's default on upgrade.
	if root := dataroots.AdoptLegacyRoot(os.Getenv, os.Setenv, func(d string) bool {
		fi, err := os.Stat(d)
		return err == nil && fi.IsDir()
	}); root != "" {
		slog.Warn("data_root.legacy_default_adopted", "root", root,
			"fix", "declare it: noo cluster set-config <node> --data-root "+root+", then noo cluster provision <node> --wait")
	}
	cfg := config.Load()

	a, err := agent.New(cfg)
	if err != nil {
		slog.Error("failed to initialize node agent", "error", err)
		os.Exit(1)
	}

	if err := a.Run(); err != nil {
		slog.Error("node agent exited with error", "error", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "warn", "WARN", "warning", "WARNING":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
