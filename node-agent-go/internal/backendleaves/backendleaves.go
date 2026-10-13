// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package backendleaves reports the backend door leaves this node HOLDS
//
// The controller can prove it holds a node's leaf for each door-backed
// backend (nodes/<id>/services/<x>/) and that the next bundle carries it.
// It cannot prove the leaf is ON the node: an agent that predates the doors
// records no refusal, and a leaf that is expiring on the node is not a
// refusal at all until the door starts failing handshakes. So the agent
// says what it has, on every heartbeat, as `backend_leaves`:
//
//	"backend_leaves": {
//	  "vllm": {"dns": ["vllm", "localhost", "noo-vllm", "noo-vllm-secondary"], "not_after": 1790000000},
//	  "tei":  {"dns": ["tei", "localhost", "noo-stunnel-tei"], "not_after": 1790000000}
//	}
//
// One entry per $NOO_PKI_DIR/services/<x>/service.crt that parses, for the
// door services only. A service with no leaf (or one that does not parse)
// is ABSENT, never an entry with nulls. The map itself is always present,
// possibly empty: that is what lets `noo cluster verify`'s `backend doors`
// row tell "holds none" from "does not report" (an older agent).
//
// Only the certificate is read. The key beside it is never opened.
package backendleaves

import (
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Services are the door services a node can hold a leaf for — the
// `service` column of noo-cli's NODE_DOOR_LEAVES (node_leaves.rs), pinned
// against it by tests/test_node_backend_leaves_on_the_rail.py. airllm is
// plaintext by named exception and has no leaf.
var Services = []string{"vllm", "llamacpp", "ollama", "tei", "reranker"}

// Leaf is what the agent reports for one held leaf: the certificate's DNS
// SANs and its NotAfter in unix seconds. The field names are the ones
// `backend_doors_check` reads (`dns`, `not_after`).
type Leaf struct {
	DNS      []string `json:"dns"`
	NotAfter int64    `json:"not_after"`
}

// fileKey identifies one version of a file on disk. A leaf is replaced by
// the applier (new inode, new mtime), so (size, mtime) moving is the only
// time the file needs parsing again.
type fileKey struct {
	size  int64
	mtime int64
}

type cached struct {
	key  fileKey
	leaf *Leaf // nil = present but does not parse
}

// Reader caches parsed leaves by path and re-parses only a file whose
// (size, mtime) moved, so a heartbeat costs one stat per service.
type Reader struct {
	mu    sync.Mutex
	cache map[string]cached
}

// NewReader returns an empty Reader.
func NewReader() *Reader { return &Reader{cache: map[string]cached{}} }

var defaultReader = NewReader()

// Report is the heartbeat's `backend_leaves` for this process's
// $NOO_PKI_DIR, through the package's shared cache.
func Report() map[string]Leaf { return defaultReader.Report(os.Getenv("NOO_PKI_DIR")) }

// Report returns the leaves held under pkiDir. Never nil: an unset pkiDir
// or one with no services/ tree yields an empty map, which is a report
// ("holds none"), not an absence.
func (r *Reader) Report(pkiDir string) map[string]Leaf {
	out := make(map[string]Leaf)
	if pkiDir == "" {
		return out
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, svc := range Services {
		if l := r.leaf(filepath.Join(pkiDir, "services", svc, "service.crt"), svc); l != nil {
			out[svc] = *l
		}
	}
	return out
}

func (r *Reader) leaf(path, svc string) *Leaf {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		delete(r.cache, path)
		return nil
	}
	k := fileKey{size: st.Size(), mtime: st.ModTime().UnixNano()}
	if c, ok := r.cache[path]; ok && c.key == k {
		return c.leaf
	}
	l, perr := parseFile(path)
	if perr != "" {
		// Logged once per file version, not once per beat.
		slog.Warn("backend_leaves.unparseable", "service", svc, "path", path, "error", perr,
			"effect", "reported as absent; `noo cluster verify` reads this node as holding no "+svc+" leaf")
	}
	r.cache[path] = cached{key: k, leaf: l}
	return l
}

// parseFile is parse, swappable so a test can count the reads the cache
// saves.
var parseFile = parse

// parse reads the first CERTIFICATE block of a PEM file. The empty string
// is success; anything else says why there is no leaf.
func parse(path string) (*Leaf, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err.Error()
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, "no PEM CERTIFICATE block"
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err.Error()
		}
		dns := cert.DNSNames
		if dns == nil {
			dns = []string{}
		}
		return &Leaf{DNS: dns, NotAfter: cert.NotAfter.Unix()}, ""
	}
}
