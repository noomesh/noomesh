// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// Refusals that another refusal used to mask, or that the table in
// TestRefusals could not reach. Each test here is written so that removing
// exactly one check turns it red.

// provisionNoPanic runs Provision and reports a panic as a failure of the
// calling test instead of killing the binary: a refusal that is gone usually
// shows up as a nil dereference further down.
func provisionNoPanic(t *testing.T, h *harness) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Provision panicked (a guard is missing): %v", r)
			err = errors.New("panic")
		}
	}()
	return h.provision()
}

// expectRefusal asserts a coded refusal that left the node and the status
// as a refusal leaves them.
func expectRefusal(t *testing.T, h *harness, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Provision succeeded, want refusal %q", reason)
	}
	if got := nodewl.CodeOf(err); got != reason {
		t.Fatalf("reason %q (%v), want %q", got, err, reason)
	}
	if len(h.api.created) != 0 {
		t.Errorf("created %d containers despite the refusal", len(h.api.created))
	}
	if st := h.p.Status("rhaddon", "worker"); st.Provisioned || st.Reason != reason {
		t.Errorf("status %+v", st)
	}
}

// Check 2: door.admit must be exactly one name. Two names whose first is this
// node's agent would otherwise pass every later check.
func TestDoorAdmitMustBeExactlyOneName(t *testing.T) {
	for name, admit := range map[string]func(d *nodewl.Door) *nodewl.Door{
		"no door":                   func(*nodewl.Door) *nodewl.Door { return nil },
		"empty admit":               func(d *nodewl.Door) *nodewl.Door { d.Admit = nil; return d },
		"two names, agent first":    func(d *nodewl.Door) *nodewl.Door { d.Admit = []string{testAgentCN, "node-b"}; return d },
		"two names, both the agent": func(d *nodewl.Door) *nodewl.Door { d.Admit = []string{testAgentCN, testAgentCN}; return d },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			d := *h.entry.Door
			h.entry.Door = admit(&d)
			err := provisionNoPanic(t, h)
			expectRefusal(t, h, err, nodewl.ReasonAdmitInvalid)
		})
	}
}

// Check 3: checkDoorPin's refusal, with no node-name cross-check in the way
// (doorSelfName nil), so the only thing that can stop it is checkDoorPin.
func TestDoorAdmitFailsCheckDoorPinOnItsOwn(t *testing.T) {
	for _, bad := range []string{"a b", "localhost", "node-agent", "", "x\nconnect = evil:1", "n;ode"} {
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			h := newHarness(t)
			h.p.doorSelfName = nil
			d := *h.entry.Door
			d.Admit = []string{bad}
			h.entry.Door = &d
			err := provisionNoPanic(t, h)
			expectRefusal(t, h, err, nodewl.ReasonAdmitInvalid)
			if h.api.mutated() {
				t.Errorf("the node was changed: %v", h.api.calls)
			}
		})
	}
	// And the accepted name provisions with the same arrangement, so the
	// refusals above are checkDoorPin's and not something else's.
	h := newHarness(t)
	h.p.doorSelfName = nil
	mustProvision(t, h)
}

// Checks 14, 15: DoorAddr names what is wrong.
func TestDoorAddrRefusals(t *testing.T) {
	door := WorkloadDoorName("rhaddon", "worker")
	net := WorkloadNetworkName("rhaddon", "worker")
	managed := map[string]string{LabelManagedBy: ManagedByAgent}
	for name, c := range map[string]struct {
		door    *ctrInfo
		wantErr string
	}{
		"no door container": {nil, "no door container"},
		"door not ours":     {&ctrInfo{ID: "x", Labels: map[string]string{"app": "mine"}, IPs: map[string]string{net: "172.30.0.9"}}, "no door container"},
		"no address":        {&ctrInfo{ID: "x", Labels: managed, IPs: map[string]string{}}, "has no address"},
		"address elsewhere": {&ctrInfo{ID: "x", Labels: managed, IPs: map[string]string{"bridge": "172.17.0.2"}}, "has no address"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			if c.door != nil {
				h.api.ctrs[door] = c.door
			}
			addr, err := func() (a string, err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic: %v", r)
					}
				}()
				return h.p.DoorAddr(context.Background(), "rhaddon", "worker")
			}()
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("DoorAddr = %q, %v; want an error containing %q", addr, err, c.wantErr)
			}
		})
	}
}

// Check 16: an unset PKI directory is its own refusal. Without it the paths
// become relative to the working directory, which here holds a good leaf.
func TestUnsetPKIDirIsRefusedNotReadRelative(t *testing.T) {
	h := newHarness(t)
	h.p.PKIDir = func() string { return "" }
	t.Chdir(h.pki)
	err := provisionNoPanic(t, h)
	expectRefusal(t, h, err, nodewl.ReasonDoorLeafMissing)
	if !strings.Contains(err.Error(), "PKI directory is not set") {
		t.Errorf("err = %v", err)
	}
}

// Check 18: a certificate file that is there but is not a certificate.
func TestUnreadableCertificateIsNamedAsSuch(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(installedLeaf(h.pki, "svc-addon-rhaddon-worker.crt"), []byte("this is not PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := provisionNoPanic(t, h)
	expectRefusal(t, h, err, nodewl.ReasonDoorLeafMissing)
	if !strings.Contains(err.Error(), "not a readable certificate") {
		t.Errorf("err = %v: an unparseable certificate must not be reported as merely naming another door", err)
	}
}

// Check 20: a slot that is not optional and has no set. Check 21: a set
// reference that is not shaped like one, before the store is asked about it.
func TestSlotsNeedSetsAndWellFormedRefs(t *testing.T) {
	for _, c := range []struct {
		name    string
		reason  string
		arrange func(h *harness)
	}{
		{"required slot has no set", nodewl.ReasonSetMissing, func(h *harness) { delete(h.entry.Sets, "main") }},
		{"required slot has an empty list", nodewl.ReasonSetMissing, func(h *harness) { h.entry.Sets["main"] = nil }},
		{"set id is a path", nodewl.ReasonSetSlotInvalid, func(h *harness) {
			h.entry.Sets["main"] = []nodewl.SetRef{{ID: "../etc", Revision: "v1"}}
			h.sets[modelsets.Ref{ID: "../etc", Revision: "v1"}] = modelsets.Status{State: modelsets.StateVerified}
		}},
		{"set revision is a path", nodewl.ReasonSetSlotInvalid, func(h *harness) {
			h.entry.Sets["main"] = []nodewl.SetRef{{ID: "rh-s2s-7b", Revision: "../x"}}
			h.sets[modelsets.Ref{ID: "rh-s2s-7b", Revision: "../x"}] = modelsets.Status{State: modelsets.StateVerified}
		}},
		{"set id empty", nodewl.ReasonSetSlotInvalid, func(h *harness) {
			h.entry.Sets["main"] = []nodewl.SetRef{{ID: "", Revision: "v1"}}
			h.sets[modelsets.Ref{ID: "", Revision: "v1"}] = modelsets.Status{State: modelsets.StateVerified}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			c.arrange(h)
			expectRefusal(t, h, provisionNoPanic(t, h), c.reason)
		})
	}
	// An optional slot with no set is fine: the refusal above is about
	// required slots only.
	h := newHarness(t)
	delete(h.entry.Sets, "voices")
	mustProvision(t, h)
}

// Check 25: a lease that holds the wrong number of devices is an error, and
// pins nothing.
func TestGPULeaseOfTheWrongSizeIsRefused(t *testing.T) {
	for _, devs := range [][]string{{"GPU-a", "GPU-b"}, {"GPU-a", "GPU-b", "GPU-c"}} {
		t.Run(fmt.Sprintf("%d devices", len(devs)), func(t *testing.T) {
			h := newHarness(t)
			h.p.GPUDevices = func(nodewl.Entry) ([]string, error) { return devs, nil }
			err := provisionNoPanic(t, h)
			if err == nil || !strings.Contains(err.Error(), "gpu lease holds") {
				t.Fatalf("err = %v, want the lease-size error", err)
			}
			if len(h.api.created) != 0 || h.api.mutated() {
				t.Errorf("a workload was provisioned on a mis-sized lease: %v", h.api.calls)
			}
		})
	}
	// Called directly: the answer carries no devices.
	h := newHarness(t)
	h.p.GPUDevices = func(nodewl.Entry) ([]string, error) { return []string{"a", "b"}, nil }
	if d, leased, err := h.p.gpuDevices(h.entry); err == nil || d != nil || leased {
		t.Errorf("gpuDevices = %v, %v, %v", d, leased, err)
	}
}

// ---- tarHoldsOneImage --------------------------------------------------

// tarOfFiles writes an archive of the named files.
func tarOfFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const (
	ociImage       = `{"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
	ociAttestation = `{"artifactType":"application/vnd.docker.attestation.manifest.v1+json"}`
)

func ociIndex(entries ...string) string {
	return `{"schemaVersion":2,"manifests":[` + strings.Join(entries, ",") + `]}`
}

// Checks 37, 38, 39: what makes an archive "one image", for both layouts.
func TestTarHoldsOneImage(t *testing.T) {
	for _, c := range []struct {
		name    string
		files   map[string]string
		wantErr string // "" = accepted
	}{
		{"docker layout, one image", map[string]string{"manifest.json": `[{"Config":"c"}]`}, ""},
		{"oci layout, one image", map[string]string{"index.json": ociIndex(ociImage)}, ""},
		{"oci layout, image and its attestation", map[string]string{"index.json": ociIndex(ociImage, ociAttestation)}, ""},
		{"oci layout, ./ prefixed", map[string]string{"./index.json": ociIndex(ociImage)}, ""},
		{"no manifest and no index", map[string]string{"layer.tar": "x", "readme": "y"}, "no manifest.json or index.json"},
		{"empty archive", map[string]string{}, "no manifest.json or index.json"},
		{"docker layout, two images", map[string]string{"manifest.json": `[{},{}]`}, "holds 2 images"},
		{"docker layout, none", map[string]string{"manifest.json": `[]`}, "holds 0 images"},
		{"oci layout, two images", map[string]string{"index.json": ociIndex(ociImage, ociImage)}, "index lists 2 images"},
		{"oci layout, none", map[string]string{"index.json": ociIndex()}, "index lists 0 images"},
		{"oci layout, only an attestation", map[string]string{"index.json": ociIndex(ociAttestation)}, "index lists 0 images"},
		{"oci layout, two images and an attestation", map[string]string{"index.json": ociIndex(ociImage, ociImage, ociAttestation)}, "index lists 2 images"},
		{"unreadable manifest.json", map[string]string{"manifest.json": "{"}, "unreadable manifest.json"},
		{"unreadable index.json", map[string]string{"index.json": "{"}, "unreadable index.json"},
		{"one image by manifest, two by index", map[string]string{"manifest.json": `[{}]`, "index.json": ociIndex(ociImage, ociImage)}, "index lists 2 images"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := tarHoldsOneImage(bytes.NewReader(tarOfFiles(t, c.files)))
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("refused: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("err = %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}
