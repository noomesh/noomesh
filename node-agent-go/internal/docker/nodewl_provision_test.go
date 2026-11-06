// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

const (
	testAgentCN  = "node-a"
	testAgentUID = 995
	imageID      = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	otherID      = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// ---- fakes -------------------------------------------------------------

type fakeProv struct {
	images  map[string]bool
	loadIDs []string
	loadErr error
	ctrs    map[string]*ctrInfo
	nets    map[string]*netInfo
	nvidia  bool
	calls   []string
	created map[string]createSpec
	volumes int
}

func newFakeProv() *fakeProv {
	return &fakeProv{images: map[string]bool{}, ctrs: map[string]*ctrInfo{}, nets: map[string]*netInfo{}, nvidia: true, created: map[string]createSpec{}}
}

func (f *fakeProv) ImageExists(_ context.Context, id string) (bool, error) {
	return f.images[id], nil
}
func (f *fakeProv) LoadImage(_ context.Context, _ *os.File) ([]string, error) {
	f.calls = append(f.calls, "load")
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	for _, id := range f.loadIDs {
		f.images[id] = true
	}
	return f.loadIDs, nil
}
func (f *fakeProv) InspectContainer(_ context.Context, name string) (*ctrInfo, error) {
	return f.ctrs[name], nil
}
func (f *fakeProv) CreateContainer(_ context.Context, s createSpec) error {
	f.calls = append(f.calls, "create:"+s.Name)
	f.created[s.Name] = s
	l := map[string]string{}
	for k, v := range s.Config.Labels {
		l[k] = v
	}
	f.ctrs[s.Name] = &ctrInfo{ID: "id-" + s.Name, Labels: l, IPs: map[string]string{WorkloadNetworkName("rhaddon", "worker"): "172.30.0.2"}}
	return nil
}
func (f *fakeProv) RemoveContainer(_ context.Context, name string) error {
	if _, ok := f.ctrs[name]; ok {
		f.calls = append(f.calls, "rm:"+name)
	}
	delete(f.ctrs, name)
	return nil
}
func (f *fakeProv) InspectNetwork(_ context.Context, name string) (*netInfo, error) {
	return f.nets[name], nil
}
func (f *fakeProv) CreateInternalNetwork(_ context.Context, name string, labels map[string]string) error {
	f.calls = append(f.calls, "net:"+name)
	f.nets[name] = &netInfo{Internal: true, Labels: labels}
	return nil
}
func (f *fakeProv) RemoveNetwork(_ context.Context, name string) error {
	if _, ok := f.nets[name]; ok {
		f.calls = append(f.calls, "rmnet:"+name)
	}
	delete(f.nets, name)
	return nil
}
func (f *fakeProv) RemoveVolumes(context.Context, string, string) error { f.volumes++; return nil }
func (f *fakeProv) NvidiaRuntime(context.Context) bool                  { return f.nvidia }

func (f *fakeProv) mutated() bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, "create:") || strings.HasPrefix(c, "rm:") || strings.HasPrefix(c, "net:") || strings.HasPrefix(c, "rmnet:") || c == "load" {
			return true
		}
	}
	return false
}

type fakeSets map[modelsets.Ref]modelsets.Status

func (s fakeSets) State(r modelsets.Ref) modelsets.Status {
	if st, ok := s[r]; ok {
		return st
	}
	return modelsets.Status{State: modelsets.StateAbsent}
}
func (s fakeSets) Dir(r modelsets.Ref) string {
	return "/var/lib/noo/models/sets/" + r.ID + "/" + r.Revision
}

type harness struct {
	t      *testing.T
	p      *NodeWorkloads
	api    *fakeProv
	sets   fakeSets
	pki    string
	entry  nodewl.Entry
	fetchN int
}

func writeLeaf(t *testing.T, dir, leaf, san string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: san}, DNSNames: []string{san},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, leaf+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	must(os.WriteFile(filepath.Join(dir, leaf+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600))
}

func fixtureEntry(t *testing.T, i int) nodewl.Entry {
	t.Helper()
	b, err := os.ReadFile("../nodewl/testdata/i300/desired-node-workloads.json")
	if err != nil {
		t.Fatal(err)
	}
	es, err := nodewl.ParseDesired(b, testAgentCN)
	if err != nil {
		t.Fatal(err)
	}
	return es[i]
}

// tarOneImage is a minimal valid image archive: one manifest.json entry.
func tarOneImage(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	m := "["
	for i := 0; i < n; i++ {
		if i > 0 {
			m += ","
		}
		m += `{"Config":"c.json","RepoTags":null,"Layers":[]}`
	}
	m += "]"
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(m))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte(m))
	_ = tw.Close()
	return buf.Bytes()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, api: newFakeProv(), pki: t.TempDir()}
	writeLeaf(t, h.pki, "svc-addon-rhaddon-worker", "noo-stunnel-rhaddon-worker")
	if err := os.WriteFile(filepath.Join(h.pki, "ca.crt"), []byte("ca"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.entry = fixtureEntry(t, 0)
	h.sets = fakeSets{
		{ID: "rh-s2s-7b", Revision: "0123456789abcdef0123456789abcdef01234567"}: {State: modelsets.StateVerified},
		{ID: "rh-voices-a", Revision: "v1"}:                                     {State: modelsets.StateVerified},
	}
	h.api.loadIDs = []string{imageID}
	tarBytes := tarOneImage(t, 1)
	h.p = &NodeWorkloads{
		Sets:     h.sets,
		PKIDir:   func() string { return h.pki },
		AgentUID: func() int { return testAgentUID },
		api:      h.api,
		goos:     "linux",
		arch:     "amd64",
		fetchTar: func(_ context.Context, artifact string) (string, func(), error) {
			h.fetchN++
			p := filepath.Join(t.TempDir(), artifact)
			if err := os.WriteFile(p, tarBytes, 0o644); err != nil {
				return "", nil, err
			}
			return p, func() {}, nil
		},
		doorImage:    func(context.Context) (string, error) { return "ghcr.io/noomesh/stunnel:test", nil },
		doorSelfName: func() (string, error) { return testAgentCN, nil },
		status:       map[string]WorkloadStatus{},
	}
	return h
}

func (h *harness) provision() error {
	h.t.Helper()
	return h.p.Provision(context.Background(), h.entry)
}

func mustProvision(t *testing.T, h *harness) (door, worker createSpec) {
	t.Helper()
	if err := h.provision(); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return h.api.created[WorkloadDoorName("rhaddon", "worker")], h.api.created[WorkloadContainerName("rhaddon", "worker")]
}

// ---- goldens -----------------------------------------------------------

func TestWorkerSpecGolden(t *testing.T) {
	h := newHarness(t)
	_, w := mustProvision(t, h)
	cfg, host := w.Config, w.Host

	if w.Name != "noo-wl-rhaddon-worker" {
		t.Errorf("name %q", w.Name)
	}
	if cfg.Image != imageID {
		t.Errorf("image %q: created from the ID, never a tag", cfg.Image)
	}
	if cfg.User != "1000" {
		t.Errorf("user %q", cfg.User)
	}
	if !reflect.DeepEqual(cfg.Cmd, []string{"rhaddon-worker"}) {
		t.Errorf("cmd %v", cfg.Cmd)
	}
	if !host.ReadonlyRootfs {
		t.Error("ReadonlyRootfs must be true")
	}
	if !reflect.DeepEqual(host.CapDrop, []string{"ALL"}) {
		t.Errorf("CapDrop %v", host.CapDrop)
	}
	if len(host.CapAdd) != 0 {
		t.Errorf("CapAdd %v: the worker adds no capability", host.CapAdd)
	}
	if !reflect.DeepEqual(host.SecurityOpt, []string{"no-new-privileges"}) {
		t.Errorf("SecurityOpt %v", host.SecurityOpt)
	}
	if host.Privileged || host.PidMode != "" || host.UTSMode != "" || host.UsernsMode != "" || host.IpcMode == "host" {
		t.Errorf("host namespaces / privileged: %+v", host)
	}
	if len(host.Binds) != 0 || len(host.Devices) != 0 || len(host.PortBindings) != 0 || host.PublishAllPorts || len(host.Tmpfs) != 0 {
		t.Errorf("binds/devices/ports/tmpfs: %+v", host)
	}
	if host.NetworkMode != "container:noo-stunnel-rhaddon-worker" {
		t.Errorf("network mode %q: the worker lives in the door's namespace", host.NetworkMode)
	}
	if cfg.Hostname != "" || len(cfg.ExposedPorts) != 0 {
		t.Errorf("hostname %q ports %v", cfg.Hostname, cfg.ExposedPorts)
	}
	if host.RestartPolicy.Name != container.RestartPolicyDisabled {
		t.Errorf("restart %q", host.RestartPolicy.Name)
	}
	r := host.Resources
	if r.Memory != 24576<<20 || r.MemorySwap != r.Memory || r.NanoCPUs != 4e9 || r.PidsLimit == nil || *r.PidsLimit != 512 {
		t.Errorf("limits %+v", r)
	}
	// The GPU request, unleased: Count, pinned in the env to indices.
	if len(r.DeviceRequests) != 1 || r.DeviceRequests[0].Driver != "nvidia" || r.DeviceRequests[0].Count != 1 || len(r.DeviceRequests[0].DeviceIDs) != 0 {
		t.Errorf("device requests %+v", r.DeviceRequests)
	}
	wantEnv := []string{
		"HF_HUB_OFFLINE=1",
		"NVIDIA_DRIVER_CAPABILITIES=compute,utility",
		"NVIDIA_VISIBLE_DEVICES=0",
		"RHADDON_LOG_AUDIO=false",
		"RHADDON_MODEL_MAIN_ID=rh-s2s-7b",
		"RHADDON_MODEL_MAIN_REVISION=0123456789abcdef0123456789abcdef01234567",
		"RHADDON_MODEL_VOICES_ID=rh-voices-a",
		"RHADDON_MODEL_VOICES_REVISION=v1",
		"RHADDON_QUANT=int8",
		"RHADDON_SLOTS=1",
		"TRANSFORMERS_OFFLINE=1",
	}
	if !reflect.DeepEqual(cfg.Env, wantEnv) {
		t.Errorf("env\n got %v\nwant %v", cfg.Env, wantEnv)
	}
	wantLabels := map[string]string{
		LabelAddon: "rhaddon", LabelWorkload: "worker", LabelManagedBy: "agent", LabelRole: "worker",
		SpecHashLabel: cfg.Labels[SpecHashLabel],
	}
	if !reflect.DeepEqual(cfg.Labels, wantLabels) || cfg.Labels[SpecHashLabel] == "" {
		t.Errorf("labels %v", cfg.Labels)
	}

	// Mounts: the two verified sets read-only, then the declared scratch. Nothing else.
	want := []struct {
		typ      mount.Type
		src, tgt string
		ro       bool
	}{
		{mount.TypeBind, "/var/lib/noo/models/sets/rh-s2s-7b/0123456789abcdef0123456789abcdef01234567", "/models/main", true},
		{mount.TypeBind, "/var/lib/noo/models/sets/rh-voices-a/v1", "/models/voices", true},
		{mount.TypeVolume, "noo-wl-rhaddon-worker-scratch0", "/cache", false},
		{mount.TypeTmpfs, "", "/tmp", false},
	}
	if len(host.Mounts) != len(want) {
		t.Fatalf("mounts %+v", host.Mounts)
	}
	for i, m := range host.Mounts {
		if m.Type != want[i].typ || m.Source != want[i].src || m.Target != want[i].tgt || m.ReadOnly != want[i].ro {
			t.Errorf("mount %d = %+v, want %+v", i, m, want[i])
		}
	}
	vol := host.Mounts[2].VolumeOptions
	if vol == nil || vol.DriverConfig == nil || vol.DriverConfig.Options["type"] != "tmpfs" ||
		!strings.Contains(vol.DriverConfig.Options["o"], "size=4096m") || !strings.Contains(vol.DriverConfig.Options["o"], "uid=1000") {
		t.Errorf("the max_mb volume is not a size-capped tmpfs-backed volume: %+v", vol)
	}
	if ts := host.Mounts[3].TmpfsOptions; ts == nil || ts.SizeBytes != 256<<20 {
		t.Errorf("tmpfs scratch %+v", host.Mounts[3].TmpfsOptions)
	}
	for _, m := range host.Mounts {
		for _, banned := range []string{"/etc/noo", "/var/run/docker.sock", "/var/lib/noo-node-agent", "pki"} {
			if strings.Contains(m.Source, banned) || strings.Contains(m.Target, banned) {
				t.Errorf("mount %+v names %q", m, banned)
			}
		}
	}
}

func TestWorkerWithoutGPUHasNoNvidiaSurface(t *testing.T) {
	h := newHarness(t)
	h.entry = fixtureEntry(t, 1) // echo: gpu 0, no models
	writeLeaf(t, h.pki, "svc-addon-rhaddon-echo", "noo-stunnel-rhaddon-echo")
	if err := h.provision(); err != nil {
		t.Fatal(err)
	}
	w := h.api.created["noo-wl-rhaddon-echo"]
	if len(w.Host.Resources.DeviceRequests) != 0 {
		t.Errorf("device requests %+v", w.Host.Resources.DeviceRequests)
	}
	for _, e := range w.Config.Env {
		if strings.HasPrefix(e, "NVIDIA_") {
			t.Errorf("env %s on a CPU workload", e)
		}
	}
	if !reflect.DeepEqual(w.Config.Env, []string{"HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1"}) {
		t.Errorf("env %v", w.Config.Env)
	}
	if w.Config.Labels[LabelReservation] != "0b1f5f0e-6a3e-4a54-9d3c-0a4e5b9c7d21" {
		t.Errorf("reservation label %v", w.Config.Labels)
	}
	if len(w.Host.Mounts) != 0 {
		t.Errorf("mounts %+v", w.Host.Mounts)
	}
}

func TestLeasedGPUIsPinnedByDeviceID(t *testing.T) {
	h := newHarness(t)
	h.p.GPUDevices = func(nodewl.Entry) ([]string, error) { return []string{"GPU-aaaa"}, nil }
	_, w := mustProvision(t, h)
	dr := w.Host.Resources.DeviceRequests
	if len(dr) != 1 || !reflect.DeepEqual(dr[0].DeviceIDs, []string{"GPU-aaaa"}) || dr[0].Count != 0 {
		t.Errorf("device requests %+v", dr)
	}
	if !hasStr(w.Config.Env, "NVIDIA_VISIBLE_DEVICES=GPU-aaaa") {
		t.Errorf("env %v", w.Config.Env)
	}
}

func hasStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestDoorSpecGolden(t *testing.T) {
	h := newHarness(t)
	d, _ := mustProvision(t, h)
	cfg, host := d.Config, d.Host

	if d.Name != "noo-stunnel-rhaddon-worker" || cfg.Hostname != d.Name {
		t.Errorf("name %q hostname %q", d.Name, cfg.Hostname)
	}
	if host.NetworkMode != "noo-wl-rhaddon-worker" || d.Net == nil || d.Net.EndpointsConfig["noo-wl-rhaddon-worker"] == nil || len(d.Net.EndpointsConfig) != 1 {
		t.Errorf("the door is on the workload's private network alone: %q %+v", host.NetworkMode, d.Net)
	}
	if len(host.PortBindings) != 0 || host.PublishAllPorts || len(cfg.ExposedPorts) != 0 {
		t.Errorf("the door publishes nothing: %+v", host.PortBindings)
	}
	if !host.ReadonlyRootfs || !reflect.DeepEqual(host.CapDrop, []string{"ALL"}) || !reflect.DeepEqual(host.CapAdd, []string{"DAC_OVERRIDE"}) ||
		!reflect.DeepEqual(host.SecurityOpt, []string{"no-new-privileges"}) || host.Privileged {
		t.Errorf("door privilege floor: %+v", host)
	}
	if host.RestartPolicy.Name != container.RestartPolicyDisabled {
		t.Errorf("restart %q", host.RestartPolicy.Name)
	}
	// stunnel's conf: client cert required from the cluster CA, the CN pinned to exactly the agent.
	var conf string
	for _, e := range cfg.Env {
		if c, ok := strings.CutPrefix(e, "STUNNEL_CONF="); ok {
			conf = c
		}
	}
	for _, need := range []string{"verify = 2", "CAfile = /tls/ca.crt", "accept = noo-stunnel-rhaddon-worker:8443", "connect = 127.0.0.1:9003",
		"cert = /tls/leaf/service.crt", "key = /tls/leaf/service.key", "checkHost = node-a\n"} {
		if !strings.Contains(conf, need) {
			t.Errorf("conf lacks %q:\n%s", need, conf)
		}
	}
	if n := strings.Count(conf, "checkHost"); n != 1 {
		t.Errorf("%d checkHost lines, want exactly the agent's:\n%s", n, conf)
	}
	for _, c := range doorCallers {
		if strings.Contains(conf, "checkHost = "+c+"\n") {
			t.Errorf("conf admits %q, a controller service", c)
		}
	}
	// Mounts: the CA and the leaf, read-only. The leaf is mounted here and in no other container.
	if len(host.Mounts) != 3 {
		t.Fatalf("mounts %+v", host.Mounts)
	}
	for _, m := range host.Mounts {
		if m.Type != mount.TypeBind || !m.ReadOnly {
			t.Errorf("mount %+v", m)
		}
	}
	if host.Mounts[1].Source != filepath.Join(h.pki, "svc-addon-rhaddon-worker.crt") || host.Mounts[2].Source != filepath.Join(h.pki, "svc-addon-rhaddon-worker.key") {
		t.Errorf("leaf sources %+v", host.Mounts)
	}
	w := h.api.created["noo-wl-rhaddon-worker"]
	for _, m := range w.Host.Mounts {
		if strings.Contains(m.Source, "svc-addon") || strings.Contains(m.Target, "/tls") {
			t.Errorf("the worker holds a leaf or the CA: %+v", m)
		}
	}
	if cfg.Labels[LabelManagedBy] != ManagedByAgent || cfg.Labels[LabelAddon] != "rhaddon" || cfg.Labels[LabelWorkload] != "worker" {
		t.Errorf("labels %v", cfg.Labels)
	}
	if d.Config.Labels[SpecHashLabel] != w.Config.Labels[SpecHashLabel] {
		t.Error("the pair shares one spec hash")
	}
}

func TestThePrivateNetworkIsInternal(t *testing.T) {
	h := newHarness(t)
	mustProvision(t, h)
	n := h.api.nets["noo-wl-rhaddon-worker"]
	if n == nil || !n.Internal || n.Labels[LabelManagedBy] != ManagedByAgent {
		t.Errorf("network %+v", n)
	}
	// Created, never started: the fake has no start call to make, and the
	// provisioner has no code path that starts.
	addr, err := h.p.DoorAddr(context.Background(), "rhaddon", "worker")
	if err != nil || addr != "172.30.0.2:8443" {
		t.Errorf("DoorAddr = %q, %v", addr, err)
	}
	if st := h.p.Status("rhaddon", "worker"); !st.Known || !st.Provisioned || st.Reason != "" || st.DoorPort != 8443 {
		t.Errorf("status %+v", st)
	}
}

// ---- refusals ----------------------------------------------------------

func TestRefusals(t *testing.T) {
	cases := []struct {
		name    string
		reason  string
		inner   string
		arrange func(h *harness)
	}{
		{"uid is the agent's", nodewl.ReasonDeclInvalid, "uid_is_agent", func(h *harness) { h.p.AgentUID = func() int { return 1000 } }},
		{"uid zero", nodewl.ReasonDeclInvalid, nodewl.CodeUIDInvalid, func(h *harness) { h.entry.Decl.UID = 0 }},
		{"door leaf missing", nodewl.ReasonDoorLeafMissing, "", func(h *harness) {
			_ = os.Remove(filepath.Join(h.pki, "svc-addon-rhaddon-worker.key"))
		}},
		{"door leaf names another door", nodewl.ReasonDoorLeafMissing, "", func(h *harness) {
			writeLeaf(h.t, h.pki, "svc-addon-rhaddon-worker", "noo-stunnel-other-worker")
		}},
		{"cluster CA missing", nodewl.ReasonDoorLeafMissing, "", func(h *harness) { _ = os.Remove(filepath.Join(h.pki, "ca.crt")) }},
		{"set absent", nodewl.ReasonSetMissing, "", func(h *harness) {
			delete(h.sets, modelsets.Ref{ID: "rh-s2s-7b", Revision: "0123456789abcdef0123456789abcdef01234567"})
		}},
		{"set not verified", nodewl.ReasonSetUnverified, "", func(h *harness) {
			h.sets[modelsets.Ref{ID: "rh-s2s-7b", Revision: "0123456789abcdef0123456789abcdef01234567"}] = modelsets.Status{State: modelsets.StateRefused, Reason: nodewl.ReasonSetUnverified}
		}},
		{"image loads as two images", nodewl.ReasonImageDigestMismatch, "", func(h *harness) { h.api.loadIDs = []string{imageID, otherID} }},
		{"loaded id differs from image.id", nodewl.ReasonImageDigestMismatch, "", func(h *harness) { h.api.loadIDs = []string{otherID} }},
		{"load yields nothing", nodewl.ReasonImageDigestMismatch, "", func(h *harness) { h.api.loadIDs = nil }},
		{"artifact arch differs from the node's", nodewl.ReasonArchMismatch, "", func(h *harness) { h.p.arch = "arm64" }},
		{"unmanaged worker container", nodewl.ReasonContainerConflict, "", func(h *harness) {
			h.api.ctrs["noo-wl-rhaddon-worker"] = &ctrInfo{ID: "x", Labels: map[string]string{"app": "mine"}}
		}},
		{"unmanaged door container", nodewl.ReasonContainerConflict, "", func(h *harness) {
			h.api.ctrs["noo-stunnel-rhaddon-worker"] = &ctrInfo{ID: "x", Labels: map[string]string{}}
		}},
		{"unmanaged network", nodewl.ReasonContainerConflict, "", func(h *harness) {
			h.api.nets["noo-wl-rhaddon-worker"] = &netInfo{Internal: true, Labels: map[string]string{}}
		}},
		{"non-linux host", nodewl.ReasonDoorUnreachable, "", func(h *harness) { h.p.goos = "darwin" }},
		{"admit is not an agent name", nodewl.ReasonAdmitInvalid, "", func(h *harness) { h.entry.Door.Admit = []string{"a b"} }},
		{"admit is not this node", nodewl.ReasonAdmitInvalid, "", func(h *harness) { h.entry.Door.Admit = []string{"node-b"} }},
		{"env out of bounds", nodewl.ReasonEnvOutOfBounds, "", func(h *harness) { h.entry.Env["RHADDON_SLOTS"] = "99" }},
		{"env collides with a slot variable", nodewl.ReasonEnvOutOfBounds, "", func(h *harness) {
			h.entry.Env["RHADDON_MODEL_MAIN_ID"] = "x"
		}},
		{"nvidia runtime absent", nodewl.ReasonNvidiaRuntimeMissing, "", func(h *harness) { h.api.nvidia = false }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			// A decl-valid collision needs the decl to allow the key.
			if strings.Contains(c.name, "collides") {
				h.entry.Decl.Env["RHADDON_MODEL_MAIN_ID"] = nodewl.EnvBound{OneOf: []string{"x"}}
			}
			c.arrange(h)
			err := h.provision()
			if err == nil {
				t.Fatal("Provision succeeded")
			}
			if got := nodewl.CodeOf(err); got != c.reason {
				t.Fatalf("reason %q (%v), want %q", got, err, c.reason)
			}
			if got := innerOf(err); got != c.inner {
				t.Errorf("inner %q, want %q", got, c.inner)
			}
			if h.api.mutated() && c.reason != nodewl.ReasonImageDigestMismatch {
				t.Errorf("a refusal changed the node: %v", h.api.calls)
			}
			for n := range h.api.created {
				t.Errorf("created %s despite the refusal", n)
			}
			if st := h.p.Status("rhaddon", "worker"); st.Provisioned || st.Reason != c.reason {
				t.Errorf("status %+v", st)
			}
		})
	}
}

func TestAnUnmanagedContainerIsNeverRemoved(t *testing.T) {
	h := newHarness(t)
	h.api.ctrs["noo-wl-rhaddon-worker"] = &ctrInfo{ID: "x", Labels: map[string]string{}}
	if err := h.p.Deprovision(context.Background(), "rhaddon", "worker"); nodewl.CodeOf(err) != nodewl.ReasonContainerConflict {
		t.Fatalf("Deprovision = %v", err)
	}
	if _, still := h.api.ctrs["noo-wl-rhaddon-worker"]; !still || h.api.mutated() {
		t.Errorf("an unmanaged container was touched: %v", h.api.calls)
	}
}

func TestSetsStillFetchingIsPendingNotARefusal(t *testing.T) {
	h := newHarness(t)
	h.sets[modelsets.Ref{ID: "rh-voices-a", Revision: "v1"}] = modelsets.Status{State: modelsets.StateFetching}
	err := h.provision()
	if !errors.Is(err, ErrSetsPending) || nodewl.CodeOf(err) != "" {
		t.Fatalf("err = %v", err)
	}
	if st := h.p.Status("rhaddon", "worker"); !st.Pending || st.Reason != "" || h.api.mutated() {
		t.Errorf("status %+v calls %v", st, h.api.calls)
	}
}

// ---- image -------------------------------------------------------------

func TestAnImageAlreadyThereIsNotLoaded(t *testing.T) {
	h := newHarness(t)
	h.api.images[imageID] = true
	mustProvision(t, h)
	if h.fetchN != 0 || hasStr(h.api.calls, "load") {
		t.Errorf("fetched %d, calls %v", h.fetchN, h.api.calls)
	}
}

func TestTheImageIsLoadedFromTheRailOnce(t *testing.T) {
	h := newHarness(t)
	mustProvision(t, h)
	if h.fetchN != 1 || !hasStr(h.api.calls, "load") {
		t.Errorf("fetched %d, calls %v", h.fetchN, h.api.calls)
	}
}

func TestATarOfTwoImagesNeverReachesDocker(t *testing.T) {
	h := newHarness(t)
	two := tarOneImage(t, 2)
	h.p.fetchTar = func(_ context.Context, a string) (string, func(), error) {
		p := filepath.Join(t.TempDir(), a)
		return p, func() {}, os.WriteFile(p, two, 0o644)
	}
	err := h.provision()
	if nodewl.CodeOf(err) != nodewl.ReasonImageDigestMismatch || hasStr(h.api.calls, "load") {
		t.Fatalf("err %v calls %v", err, h.api.calls)
	}
}

func TestRailFailuresMapToTheirReasons(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		reason string
	}{
		"not staged":        {ErrArtifactAbsent, nodewl.ReasonImageMissing},
		"sha256 mismatch":   {&ImageVerificationError{Ref: "x", Err: errors.New("sha")}, nodewl.ReasonImageDigestMismatch},
		"transport failure": {errors.New("timeout"), ""},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.p.fetchTar = func(context.Context, string) (string, func(), error) { return "", nil, c.err }
			err := h.provision()
			if err == nil || nodewl.CodeOf(err) != c.reason {
				t.Fatalf("err %v, want reason %q", err, c.reason)
			}
		})
	}
}

func TestCheckTarOneImage(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := checkTarOneImage(write("one.tar", tarOneImage(t, 1))); err != nil {
		t.Errorf("one image: %v", err)
	}
	if err := checkTarOneImage(write("two.tar", tarOneImage(t, 2))); err == nil {
		t.Error("two images accepted")
	}
	if err := checkTarOneImage(write("junk.tar", []byte("not a tar at all"))); err == nil {
		t.Error("junk accepted")
	}
}

// ---- idempotence and recreation ----------------------------------------

func TestProvisionIsIdempotent(t *testing.T) {
	h := newHarness(t)
	mustProvision(t, h)
	h.api.calls = nil
	h.fetchN = 0
	if err := h.provision(); err != nil {
		t.Fatal(err)
	}
	if h.api.mutated() || h.fetchN != 0 {
		t.Errorf("a matching pair was touched: %v", h.api.calls)
	}
}

func TestASpecChangeRecreatesBothStopped(t *testing.T) {
	for name, change := range map[string]func(h *harness){
		"env":      func(h *harness) { h.entry.Env["RHADDON_SLOTS"] = "2" },
		"image id": func(h *harness) { h.entry.Image.ID = otherID; h.api.loadIDs = []string{otherID} },
		"set revision": func(h *harness) {
			h.entry.Sets["voices"] = []nodewl.SetRef{{ID: "rh-voices-a", Revision: "v2"}}
			h.sets[modelsets.Ref{ID: "rh-voices-a", Revision: "v2"}] = modelsets.Status{State: modelsets.StateVerified}
		},
		"leaf re-issued": func(h *harness) { writeLeaf(h.t, h.pki, "svc-addon-rhaddon-worker", "noo-stunnel-rhaddon-worker") },
		"reservation":    func(h *harness) { r := "0b1f5f0e-6a3e-4a54-9d3c-0a4e5b9c7d21"; h.entry.Reservation = &r },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			mustProvision(t, h)
			old := h.api.ctrs["noo-wl-rhaddon-worker"].Labels[SpecHashLabel]
			h.api.calls = nil
			change(h)
			if err := h.provision(); err != nil {
				t.Fatal(err)
			}
			want := []string{"rm:noo-wl-rhaddon-worker", "rm:noo-stunnel-rhaddon-worker", "rmnet:noo-wl-rhaddon-worker", "net:noo-wl-rhaddon-worker", "create:noo-stunnel-rhaddon-worker", "create:noo-wl-rhaddon-worker"}
			var got []string
			for _, c := range h.api.calls {
				if c != "load" {
					got = append(got, c)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("calls\n got %v\nwant %v", got, want)
			}
			if h.api.ctrs["noo-wl-rhaddon-worker"].Labels[SpecHashLabel] == old {
				t.Error("the recreated worker carries the old spec hash")
			}
			if h.api.volumes < 2 {
				t.Errorf("scratch volumes removed %d times", h.api.volumes)
			}
			if h.api.ctrs["noo-wl-rhaddon-worker"].Running {
				t.Error("recreated running")
			}
		})
	}
}

func TestARunningWorkerIsNeverRecreated(t *testing.T) {
	h := newHarness(t)
	mustProvision(t, h)
	h.api.ctrs["noo-wl-rhaddon-worker"].Running = true
	h.api.calls = nil
	h.entry.Env["RHADDON_SLOTS"] = "2"
	if err := h.provision(); !errors.Is(err, ErrWorkerRunning) {
		t.Fatalf("err = %v", err)
	}
	if h.api.mutated() {
		t.Errorf("a live session was touched: %v", h.api.calls)
	}
	// The same spec while running is simply fine.
	h.entry.Env["RHADDON_SLOTS"] = "1"
	if err := h.provision(); err != nil {
		t.Fatalf("matching running pair: %v", err)
	}
}

func TestARefusalKeepsTheLastGoodState(t *testing.T) {
	h := newHarness(t)
	mustProvision(t, h)
	_ = os.Remove(filepath.Join(h.pki, "svc-addon-rhaddon-worker.key"))
	h.api.calls = nil
	if err := h.provision(); nodewl.CodeOf(err) != nodewl.ReasonDoorLeafMissing {
		t.Fatalf("err = %v", err)
	}
	st := h.p.Status("rhaddon", "worker")
	if !st.Provisioned || st.Reason != nodewl.ReasonDoorLeafMissing || h.api.mutated() {
		t.Errorf("status %+v calls %v", st, h.api.calls)
	}
}

func TestDeprovision(t *testing.T) {
	h := newHarness(t)
	mustProvision(t, h)
	h.api.calls = nil
	if err := h.p.Deprovision(context.Background(), "rhaddon", "worker"); err != nil {
		t.Fatal(err)
	}
	want := []string{"rm:noo-wl-rhaddon-worker", "rm:noo-stunnel-rhaddon-worker", "rmnet:noo-wl-rhaddon-worker"}
	if !reflect.DeepEqual(h.api.calls, want) {
		t.Errorf("calls %v", h.api.calls)
	}
	if st := h.p.Status("rhaddon", "worker"); st.Known {
		t.Errorf("status %+v", st)
	}
	if err := h.p.Deprovision(context.Background(), "rhaddon", "worker"); err != nil {
		t.Errorf("deprovisioning what is absent: %v", err)
	}
}

func TestArtifactArch(t *testing.T) {
	if got := artifactArch("noo-addon-wl_a_b_" + strings.Repeat("f", 64) + "_arm64.tar"); got != "arm64" {
		t.Errorf("arch %q", got)
	}
}

// tempSets is a set store whose sealed dirs are real directories under one
// t.TempDir(), laid out as the archive is: <root>/<id>/<rev>/<files>.
type tempSets struct{ root string }

func (s tempSets) State(modelsets.Ref) modelsets.Status {
	return modelsets.Status{State: modelsets.StateVerified}
}
func (s tempSets) Dir(r modelsets.Ref) string { return filepath.Join(s.root, r.ID, r.Revision) }

// TestSetMountKeepsTheSetLayoutUnderTheSlotTarget pins the contract a worker
// relies on: a set file P in a slot with target T is seen at exactly T/P. A
// many:false slot binds its set's ROOT at the target; a many:true slot binds
// each set at <target>/<set id>. Every set bind is read-only.
func TestSetMountKeepsTheSetLayoutUnderTheSlotTarget(t *testing.T) {
	h := newHarness(t)
	store := tempSets{root: t.TempDir()}
	refs := map[string]modelsets.Ref{
		"voices": {ID: "rh-voices-a", Revision: "v1"},
		"x1":     {ID: "rh-extra-1", Revision: "v1"},
		"x2":     {ID: "rh-extra-2", Revision: "v1"},
	}
	for _, r := range refs {
		if err := os.MkdirAll(filepath.Join(store.Dir(r), "voices"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	voiceFile := filepath.Join(store.Dir(refs["voices"]), "voices", "a.pt")
	if err := os.WriteFile(voiceFile, []byte("pt"), 0o644); err != nil {
		t.Fatal(err)
	}
	acc := &nodewl.Accepts{Kind: "voice-pack"}
	h.entry.Decl.Models = []nodewl.Slot{
		{Slot: "voices", Target: "/models/voice-pack", Accepts: acc, Many: false},
		{Slot: "extras", Target: "/models/extras", Accepts: acc, Many: true},
	}
	h.entry.Sets = map[string][]nodewl.SetRef{
		"voices": {{ID: refs["voices"].ID, Revision: refs["voices"].Revision}},
		"extras": {{ID: refs["x1"].ID, Revision: refs["x1"].Revision}, {ID: refs["x2"].ID, Revision: refs["x2"].Revision}},
	}
	h.p.Sets = store

	_, w := mustProvision(t, h)

	binds := map[string]mount.Mount{}
	for _, m := range w.Host.Mounts {
		if m.Type != mount.TypeBind {
			continue
		}
		binds[m.Target] = m
		if !m.ReadOnly {
			t.Errorf("set bind at %s is not read-only", m.Target)
		}
	}
	// (a) many:false: the set ROOT at exactly the slot target.
	m, ok := binds["/models/voice-pack"]
	if !ok {
		t.Fatalf("no bind at /models/voice-pack; binds: %v", binds)
	}
	if m.Source != store.Dir(refs["voices"]) {
		t.Errorf("many:false source %q, want the set root %q (not a sub-directory)", m.Source, store.Dir(refs["voices"]))
	}
	// The worker sees Target/voices/a.pt; on disk that is Source/voices/a.pt.
	if _, err := os.Stat(filepath.Join(m.Source, "voices", "a.pt")); err != nil {
		t.Errorf("Source %q does not hold voices/a.pt, so the worker would not see /models/voice-pack/voices/a.pt: %v", m.Source, err)
	}
	// (b) many:true: <target>/<set id> for each set, each rooted at its own set.
	for _, k := range []string{"x1", "x2"} {
		want := "/models/extras/" + refs[k].ID
		b, ok := binds[want]
		if !ok {
			t.Errorf("no bind at %s; binds: %v", want, binds)
			continue
		}
		if b.Source != store.Dir(refs[k]) {
			t.Errorf("many:true source %q, want %q", b.Source, store.Dir(refs[k]))
		}
	}
}
