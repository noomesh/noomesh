// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodepolicy"
)

// i596: desired-config's `workload_approvals` reaches the verifier before any
// node workload is judged, and nothing the gateway sends can remove a held set.

// fleetKey writes signing.pub beside a cluster CA path in a fresh PKI dir, as
// /etc/noo/pki holds both, and returns the private key and the config.
func fleetKey(t *testing.T, node string) (*ecdsa.PrivateKey, *config.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pki := t.TempDir()
	if err := os.WriteFile(filepath.Join(pki, "signing.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return priv, &config.Config{NodeID: node, StateDir: t.TempDir(), TLSCA: filepath.Join(pki, "ca.crt")}
}

// delivery is desired-config's field for a set of generation gen.
func delivery(t *testing.T, priv *ecdsa.PrivateKey, node string, gen int64, a ...nodepolicy.Approval) json.RawMessage {
	t.Helper()
	if a == nil {
		a = []nodepolicy.Approval{}
	}
	doc, err := json.Marshal(nodepolicy.ControllerSet{Kind: nodepolicy.ControllerSetKind, Node: node, Generation: gen, IssuedAt: "2026-11-08T12:00:00Z", Approvals: a})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(doc)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"doc": base64.StdEncoding.EncodeToString(doc), "sig": base64.StdEncoding.EncodeToString(sig)})
	return b
}

func heldFile(t *testing.T, cfg *config.Config) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cfg.StateDir, nodepolicy.ControllerApprovalsFile))
	if err != nil {
		t.Fatalf("no held set: %v", err)
	}
	return b
}

func offer(r *Reconciler, raw json.RawMessage) {
	r.offerWorkloadApprovals(context.Background(), &tick{desired: &desiredConfig{WorkloadApprovals: raw}})
}

func TestTheApprovalSetIsOfferedBeforeNodeWorkloadsAreJudged(t *testing.T) {
	at := map[string]int{}
	for i, ph := range reconcilePhases {
		at[ph.name] = i
	}
	o, ok := at["offerWorkloadApprovals"]
	if !ok {
		t.Fatal("no phase offers desired-config's workload_approvals")
	}
	if !(at["fetchDesired"] < o && o < at["convergeNodeWorkloads"]) {
		t.Fatalf("offer at %d; fetch at %d, node workloads at %d", o, at["fetchDesired"], at["convergeNodeWorkloads"])
	}
}

func TestAnAbsentOrNullDeliveryKeepsTheHeldSet(t *testing.T) {
	priv, cfg := fleetKey(t, "n1")
	r := &Reconciler{cfg: cfg, ctlApprovals: newControllerApprovals(cfg)}
	offer(r, delivery(t, priv, "n1", 3))
	before := heldFile(t, cfg)
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null"), json.RawMessage(" null ")} {
		offer(r, raw)
		if !bytes.Equal(heldFile(t, cfg), before) {
			t.Fatalf("%q changed the held set", raw)
		}
	}
}

func TestARefusedDeliveryKeepsTheHeldSetAndThePassGoesOn(t *testing.T) {
	priv, cfg := fleetKey(t, "n1")
	r := &Reconciler{cfg: cfg, ctlApprovals: newControllerApprovals(cfg)}
	offer(r, delivery(t, priv, "n1", 2))
	before := heldFile(t, cfg)
	other, _ := fleetKey(t, "n1")
	for name, raw := range map[string]json.RawMessage{
		"older generation": delivery(t, priv, "n1", 1),
		"another node":     delivery(t, priv, "n2", 9),
		"another key":      delivery(t, other, "n1", 9),
		"not a delivery":   json.RawMessage(`{"doc":"%%%","sig":""}`),
		"not an object":    json.RawMessage(`"revoke everything"`),
	} {
		if !r.offerWorkloadApprovals(context.Background(), &tick{desired: &desiredConfig{WorkloadApprovals: raw}}) {
			t.Fatalf("%s: the pass stopped", name)
		}
		if !bytes.Equal(heldFile(t, cfg), before) {
			t.Fatalf("%s: changed the held set", name)
		}
	}
	offer(r, delivery(t, priv, "n1", 3))
	if bytes.Equal(heldFile(t, cfg), before) {
		t.Fatal("a newer set was not taken")
	}
}

// The agent binds the set to cfg.NodeID, the id it fetches desired-config
// for, and verifies it with signing.pub beside its cluster CA.
func TestTheAgentsSetIsBoundToItsNodeIDAndItsPKI(t *testing.T) {
	priv, cfg := fleetKey(t, "gpu-2")
	c := newControllerApprovals(cfg)
	doc, sig, err := nodepolicy.DecodeDelivery(delivery(t, priv, "gpu-2", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Offer(doc, sig); err != nil {
		t.Fatalf("the node's own set: %v", err)
	}
	doc, sig, _ = nodepolicy.DecodeDelivery(delivery(t, priv, "gpu-3", 2))
	if _, _, err := c.Offer(doc, sig); err == nil {
		t.Fatal("a set for another node was taken")
	}
}

func TestTheGateAndTheFactsShareTheAgentsControllerSet(t *testing.T) {
	_, cfg := fleetKey(t, "n1")
	_, facts := newNodeWorkloads(cfg, nil, nil)
	if facts.Controller == nil {
		t.Fatal("the facts carry no controller set")
	}
	g := newGate(cfg, nodepolicy.ModeApprove, nodepolicy.NewApprovals(cfg.StateDir), facts.Controller, nil, facts, nil)
	if g.Controller != facts.Controller {
		t.Fatal("the gate does not consult the controller set")
	}
}

// End to end through the fetch: a set in desired-config is held after the
// pass's first two phases, so the node workloads phase sees it.
func TestADesiredConfigSetIsHeldBeforeNodeWorkloadsConverge(t *testing.T) {
	priv, cfg := fleetKey(t, "n1")
	raw := delivery(t, priv, "n1", 1, nodepolicy.Approval{Addon: "rhaddon", Digest: gateDigest})
	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"placements":[],"workload_approvals":` + string(raw) + `}`))
	}))
	t.Cleanup(ctl.Close)
	cfg.ControllerURL = ctl.URL
	r := New(cfg, nil, ctl.Client(), nil)
	facts := r.facts
	tk := &tick{}
	for _, ph := range reconcilePhases {
		if ph.name == "convergeNodeWorkloads" {
			break
		}
		if ph.name == "fetchDesired" || ph.name == "offerWorkloadApprovals" {
			if !ph.run(r, context.Background(), tk) {
				t.Fatalf("%s stopped the pass", ph.name)
			}
		}
	}
	if st := facts.Controller.Status(); st["set_state"] != "verified" || st["generation"] != int64(1) {
		t.Fatalf("held after the fetch: %v", st)
	}
}
