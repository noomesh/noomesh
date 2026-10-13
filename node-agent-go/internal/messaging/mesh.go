// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package messaging

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// meshDiscoverSubject is the canonical discovery subject. It MUST match the
// requesters: the Rust gateway (mesh/router.rs DISCOVER_SUBJECT) and Python
// mesh_router.py MESH_DISCOVER_SUBJECT both use "mesh.inference.discover".
// This subscriber previously listened on "mesh.discover", which nothing
// publishes — discovery requests never reached Go agents.
const meshDiscoverSubject = "mesh.inference.discover"

// meshResponderQueue is the queue group shared by all responders so a
// request/reply discover is answered once per node pool member, matching
// Python MeshResponder (queue="mesh_responders").
const meshResponderQueue = "mesh_responders"

// MeshResponder responds to backend discovery queries from other nodes.
// Matches Python MeshResponder behavior.
type MeshResponder struct {
	client      *Client
	nodeID      string
	getBackends func() map[string]BackendInfo
	getLoad     func() float64

	subMu          sync.Mutex
	sub            *nats.Subscription
	hookRegistered bool
}

// BackendInfo describes a running backend for mesh discovery.
type BackendInfo struct {
	Model     string `json:"model"`
	URL       string `json:"url"`
	APIFormat string `json:"api_format"`
}

// NewMeshResponder creates a mesh responder.
func NewMeshResponder(
	client *Client,
	nodeID string,
	getBackends func() map[string]BackendInfo,
	getLoad func() float64,
) *MeshResponder {
	return &MeshResponder{
		client:      client,
		nodeID:      nodeID,
		getBackends: getBackends,
		getLoad:     getLoad,
	}
}

// discoverRequest is the request payload published by gateways
// ({"type": "discover", "model": ..., "backend_type": ...}).
type discoverRequest struct {
	Model       string `json:"model"`
	BackendType string `json:"backend_type"`
}

// buildOffer picks the first backend satisfying the request filters and
// returns the canonical offer payload the requesters deserialize
// (Rust BackendOffer / Python _select_best candidates). Returns nil when
// nothing matches or the node is shedding load (load > 0.95), in which
// case the responder stays silent and the requester times out over to the
// next resolution stage. Pure function so the reply contract is testable
// without NATS.
func buildOffer(
	nodeID string,
	backends map[string]BackendInfo,
	load float64,
	req discoverRequest,
) map[string]any {
	if load > 0.95 {
		return nil // too loaded, don't respond (matches Python)
	}
	for backendType, info := range backends {
		if req.Model != "" && info.Model != req.Model {
			continue
		}
		if req.BackendType != "" && backendType != req.BackendType {
			continue
		}
		if info.URL == "" {
			continue
		}
		apiFormat := info.APIFormat
		if apiFormat == "" {
			apiFormat = "openai"
		}
		return map[string]any{
			"type":         "offer",
			"node_id":      nodeID,
			"backend_type": backendType,
			"model":        info.Model,
			"url":          info.URL,
			"load":         load,
			"api_format":   apiFormat,
			"ts":           time.Now().Unix(),
		}
	}
	return nil
}

// Start begins responding to mesh discovery requests.
//
// Registers a reconnect hook first. nats.go replays core subscriptions
// across an ordinary reconnect, but not across a watchdog-driven connection
// rebuild (a brand-new *nats.Conn), and a subscribe that fails because the
// bus was down at startup would otherwise never be retried — leaving the
// node undiscoverable while it looks perfectly healthy over HTTP.
func (m *MeshResponder) Start() error {
	m.subMu.Lock()
	register := !m.hookRegistered
	m.hookRegistered = true
	m.subMu.Unlock()
	if register {
		m.client.OnReconnect(func() {
			if err := m.bind(); err != nil {
				slog.Error("mesh responder resubscribe failed", "node_id", m.nodeID, "error", err)
			} else {
				slog.Info("mesh responder resubscribed after reconnect", "node_id", m.nodeID)
			}
		})
	}

	if err := m.bind(); err != nil {
		if !m.client.IsConnected() {
			slog.Warn("mesh responder subscribe deferred until nats connects",
				"node_id", m.nodeID, "error", err)
			return nil
		}
		return err
	}
	return nil
}

// bind (re)creates the discovery subscription, dropping any previous one.
func (m *MeshResponder) bind() error {
	nc := m.client.NC()
	if nc == nil {
		return ErrNotConnected
	}

	sub, err := nc.QueueSubscribe(meshDiscoverSubject, meshResponderQueue, func(msg *nats.Msg) {
		var req discoverRequest
		_ = json.Unmarshal(msg.Data, &req) // empty filters on parse failure

		offer := buildOffer(m.nodeID, m.getBackends(), m.getLoad(), req)
		if offer == nil {
			return // nothing to offer — stay silent so the requester times out
		}

		data, err := json.Marshal(offer)
		if err != nil {
			return
		}
		msg.Respond(data)
	})
	if err != nil {
		return err
	}

	m.subMu.Lock()
	old := m.sub
	m.sub = sub
	m.subMu.Unlock()
	if old != nil {
		old.Unsubscribe()
	}

	slog.Info("mesh responder started", "node_id", m.nodeID, "subject", meshDiscoverSubject)
	return nil
}

// Bound reports whether the discovery subscription is currently live.
func (m *MeshResponder) Bound() bool {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	return m.sub != nil && m.sub.IsValid()
}

// Stop unsubscribes from mesh discovery.
func (m *MeshResponder) Stop() {
	m.subMu.Lock()
	sub := m.sub
	m.sub = nil
	m.subMu.Unlock()
	if sub != nil {
		sub.Unsubscribe()
	}
}

// GossipAnnouncer periodically broadcasts node state to peers.
// Matches Python GossipMesh behavior.
type GossipAnnouncer struct {
	client      *Client
	nodeID      string
	getAnnounce func() map[string]any
	interval    time.Duration
	done        chan struct{}
}

// NewGossipAnnouncer creates a gossip announcer.
func NewGossipAnnouncer(
	client *Client,
	nodeID string,
	getAnnounce func() map[string]any,
	interval time.Duration,
) *GossipAnnouncer {
	return &GossipAnnouncer{
		client:      client,
		nodeID:      nodeID,
		getAnnounce: getAnnounce,
		interval:    interval,
		done:        make(chan struct{}),
	}
}

// Start begins periodic gossip announcements.
func (g *GossipAnnouncer) Start() {
	go func() {
		ticker := time.NewTicker(g.interval)
		defer ticker.Stop()

		missed := 0
		for {
			select {
			case <-g.done:
				return
			case <-ticker.C:
				// The gateway derives node liveness from these announcements
				// (routes/cluster.rs: in KV but not an alive gossip peer =>
				// "unknown"). A silent stop is therefore the visible symptom
				// of bus-deafness — say so in the log rather than dropping
				// the publish into a closed connection with `_ =`.
				nc := g.client.NC()
				if nc == nil || !nc.IsConnected() {
					missed++
					if missed == 1 || missed%10 == 0 {
						slog.Warn("gossip announce skipped — nats not connected",
							"node_id", g.nodeID, "missed", missed)
					}
					continue
				}
				if missed > 0 {
					slog.Info("gossip announce resumed", "node_id", g.nodeID, "missed", missed)
					missed = 0
				}

				data := g.getAnnounce()
				data["node_id"] = g.nodeID
				data["type"] = "announce"
				data["timestamp"] = time.Now().Unix()

				payload, err := json.Marshal(data)
				if err != nil {
					continue
				}
				// NODE-SCOPED subject. Per-principal bus credentials
				// grant this node
				// `mesh.gossip.announce.<id>` and nothing wider, so the bare
				// subject this used to publish was REFUSED by the server.
				// NATS reports permission violations asynchronously, so
				// Publish returned nil, nothing was logged, and gossip just
				// stopped — the gateway saw no alive peer, marked the node
				// `unknown`, and `has_capacity` (which requires Online) made
				// it undispatchable while it still heartbeat and reported a
				// connected bus. host3 and host9, 2026-09-05.
				//
				// The gateway subscribes to both this and the bare subject,
				// so an older agent keeps working; it also checks this id
				// against the payload, which is what makes a scoped announce
				// attributable at all.
				if err := nc.Publish(gossipAnnounceSubject(g.nodeID), payload); err != nil {
					slog.Warn("gossip announce failed", "node_id", g.nodeID, "error", err)
				}
			}
		}
	}()
	slog.Info("gossip announcer started", "node_id", g.nodeID, "interval", g.interval)
}

// gossipAnnounceSubject builds this node's announce subject.
//
// The id is used RAW, exactly as the credential's `mesh.gossip.announce.{id}`
// grant renders it and as every `events.job.*.{id}` subject already does. A
// node id containing a dot would split into extra tokens and match neither the
// grant nor the gateway's single-token wildcard — but that is already true of
// the whole per-principal subject scheme, so it is a fleet-wide naming
// constraint, not something to paper over differently in this one place.
func gossipAnnounceSubject(nodeID string) string {
	return "mesh.gossip.announce." + nodeID
}

// Stop stops gossip announcements.
func (g *GossipAnnouncer) Stop() {
	close(g.done)
}

// NOTE (2026-08 zombie sweep): a MeshRegistryPublisher used to live here. It
// created a "mesh_registry" NATS KV bucket at startup and had a
// PublishHeartbeat method that was never called — and both the bucket name
// and the "node.<id>" key format disagreed with the real registry the Rust
// gateway reads ("mesh_nodes" bucket, plain node_id keys, written via the
// HTTP heartbeat path). Deleted as dead, state-misrepresenting code.
