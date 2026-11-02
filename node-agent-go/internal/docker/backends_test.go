// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"

	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

func TestResolveEnv_Simple(t *testing.T) {
	os.Setenv("TEST_VAR_1", "hello")
	defer os.Unsetenv("TEST_VAR_1")

	got := resolveEnv("${TEST_VAR_1}")
	if got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
}

func TestResolveEnv_Default(t *testing.T) {
	os.Unsetenv("TEST_VAR_UNSET")

	got := resolveEnv("${TEST_VAR_UNSET:-fallback}")
	if got != "fallback" {
		t.Errorf("expected 'fallback', got %q", got)
	}
}

func TestResolveEnv_EnvOverridesDefault(t *testing.T) {
	os.Setenv("TEST_VAR_2", "from-env")
	defer os.Unsetenv("TEST_VAR_2")

	got := resolveEnv("${TEST_VAR_2:-default}")
	if got != "from-env" {
		t.Errorf("expected 'from-env', got %q", got)
	}
}

func TestResolveEnv_Nested(t *testing.T) {
	os.Unsetenv("OUTER")
	os.Setenv("INNER", "/data/models")
	defer os.Unsetenv("INNER")

	got := resolveEnv("${OUTER:-${INNER}/cache}")
	if got != "/data/models/cache" {
		t.Errorf("expected '/data/models/cache', got %q", got)
	}
}

func TestResolveEnv_NoSubstitution(t *testing.T) {
	got := resolveEnv("plain-string")
	if got != "plain-string" {
		t.Errorf("expected 'plain-string', got %q", got)
	}
}

func TestResolveEnv_EmptyDefault(t *testing.T) {
	os.Unsetenv("TEST_EMPTY_DEFAULT")

	got := resolveEnv("${TEST_EMPTY_DEFAULT:-}")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestBackendSpecs_AllKnownBackends(t *testing.T) {
	expected := []string{"vllm", "llamacpp", "ollama", "airllm", "embedding"}
	for _, name := range expected {
		spec, ok := backendSpecs[name]
		if !ok {
			t.Errorf("backend %q not found in specs", name)
			continue
		}
		if spec.Image == "" {
			t.Errorf("backend %q has empty image", name)
		}
		if spec.ContainerName == "" {
			t.Errorf("backend %q has empty container name", name)
		}
		if spec.Network == "" {
			t.Errorf("backend %q has empty network", name)
		}
	}
}

func TestBackendSpecs_ContainerNames(t *testing.T) {
	cases := map[string]string{
		"vllm":      "noo-vllm",
		"llamacpp":  "noo-llamacpp",
		"ollama":    "noo-ollama",
		"airllm":    "noo-airllm",
		"embedding": "noo-tei",
	}
	for backend, expectedName := range cases {
		if backendSpecs[backend].ContainerName != expectedName {
			t.Errorf("backend %q: expected container %q, got %q",
				backend, expectedName, backendSpecs[backend].ContainerName)
		}
	}
}

func TestParseGPUCount(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"all", -1},
		{"1", 1},
		{"2", 2},
		{"0", 0},
	}

	for _, tc := range cases {
		got := parseGPUCount(tc.input)
		if got != tc.want {
			t.Errorf("parseGPUCount(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestBuildEnvList(t *testing.T) {
	specEnv := map[string]string{
		"KEY1": "value1",
		"KEY2": "value2",
	}
	overrides := map[string]string{
		"KEY2": "overridden",
		"KEY3": "new",
	}

	env := buildEnvList(specEnv, overrides)

	envMap := map[string]string{}
	for _, e := range env {
		for i, c := range e {
			if c == '=' {
				envMap[e[:i]] = e[i+1:]
				break
			}
		}
	}

	if envMap["KEY1"] != "value1" {
		t.Errorf("KEY1 should be 'value1', got %q", envMap["KEY1"])
	}
	if envMap["KEY2"] != "overridden" {
		t.Errorf("KEY2 should be 'overridden', got %q", envMap["KEY2"])
	}
	if envMap["KEY3"] != "new" {
		t.Errorf("KEY3 should be 'new', got %q", envMap["KEY3"])
	}
}

func TestBuildMounts_SkipsPlaceholder(t *testing.T) {
	vols := []VolumeMount{
		{Source: "/real/path", Target: "/app/data"},
		{Source: "./.pki-placeholder", Target: "/app/pki", ReadOnly: true},
	}

	mounts, skipped := buildMounts(vols)

	if len(mounts) != 1 {
		t.Errorf("expected 1 mount (placeholder skipped), got %d", len(mounts))
	}
	if len(mounts) > 0 && mounts[0].Source != "/real/path" {
		t.Errorf("expected source '/real/path', got %q", mounts[0].Source)
	}
	if len(skipped) != 1 || skipped[0].Target != "/app/pki" {
		t.Errorf("the skipped placeholder must be reported, got %+v", skipped)
	}
}

// writePKIDir lays out a PKI directory of the given shape under a temp root
// and returns it. "controller" is $NOO_PKI_DIR on the controller (CA key,
// every node's leaf, every service leaf); "worker" is /etc/noo/pki on a
// provisioned node, exactly what build_signed_cert_bundle delivers: ca.crt,
// nodes/<id>/node.{crt,key}, signing.pub — no services/ at all.
func writePKIDir(t *testing.T, shape string) string {
	t.Helper()
	root := t.TempDir()
	touch := func(rel string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A service leaf is a REAL certificate here: backendDoorCheck parses it
	// for the SANs the door is dialled by (the same names onboard issues:
	// noo-<svc>, noo-stunnel-<svc>, localhost).
	leaf := func(svc string, sans ...string) {
		t.Helper()
		dir := filepath.Join(root, "services", svc)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		crt, key := selfSignedLeaf(t, sans)
		if err := os.WriteFile(filepath.Join(dir, "service.crt"), crt, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "service.key"), key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	switch shape {
	case "controller":
		touch("ca.crt")
		touch("ca.key")
		touch("signing.key")
		touch("gateway/gateway.crt")
		touch("gateway/gateway.key")
		touch("nodes/host3/node.crt")
		touch("nodes/host3/node.key")
		touch("nodes/host8/node.crt")
		touch("nodes/host8/node.key")
		for _, svc := range []string{"vllm", "llamacpp", "ollama", "tei", "reranker", "redis", "nats", "postgres"} {
			leaf(svc, svc, "localhost", "noo-"+svc, "noo-stunnel-"+svc)
		}
	case "controller-wrong-san":
		// Leaves issued by hand without the door names — what `noo security
		// pki issue-service vllm` yields with no --san.
		touch("ca.crt")
		for _, svc := range []string{"vllm", "llamacpp", "ollama", "tei", "reranker"} {
			leaf(svc, svc, "localhost")
		}
	case "worker":
		touch("ca.crt")
		touch("signing.pub")
		touch("nodes/host3/node.crt")
		touch("nodes/host3/node.key")
	default:
		t.Fatalf("unknown shape %q", shape)
	}
	return root
}

// selfSignedLeaf mints a throwaway certificate naming `sans`, PEM-encoded.
func selfSignedLeaf(t *testing.T, sans []string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sans[0], Organization: []string{"Mesh Cluster Service"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     sans,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

// pkiMountsOf runs buildMounts over a backend spec's volumes with
// NOO_PKI_DIR pointed at dir and returns the resulting mounts whose target
// is under /app/pki, keyed by target.
func pkiMountsOf(t *testing.T, backend, dir string) map[string]string {
	t.Helper()
	spec, ok := backendSpecs[backend]
	if !ok {
		t.Fatalf("no spec for %s", backend)
	}
	t.Setenv("NOO_PKI_DIR", dir)
	mounts, _ := buildMounts(spec.Volumes)
	out := map[string]string{}
	for _, m := range mounts {
		if strings.HasPrefix(m.Target, "/app/pki") {
			out[m.Target] = m.Source
		}
	}
	return out
}

// #506 narrowed every compose PKI mount to ca.crt + the service's own leaf;
// the agent's specs still bind-mounted the WHOLE directory into the
// backends it starts on nodes, so a worker's vllm/llamacpp/reranker held
// that node's nodes/<id>/node.key. This pins the narrowing per backend and
// per PKI-dir shape. A backend's PKI is only what it serves with, and no
// engine the agent starts serves TLS: every door is a sidecar (vLLM's since
// door generation 5), which mounts the leaf itself.
func TestPKIMounts_NarrowedPerBackend(t *testing.T) {
	controller := writePKIDir(t, "controller")
	worker := writePKIDir(t, "worker")
	missing := filepath.Join(t.TempDir(), "never-created")

	cases := []struct {
		backend string
		dir     string
		want    map[string]string // target -> source relative to dir
	}{
		{"vllm", controller, map[string]string{}},
		{"vllm", worker, map[string]string{}},
		{"vllm", missing, map[string]string{}},
		{"llamacpp", controller, map[string]string{}},
		{"llamacpp", worker, map[string]string{}},
		{"llamacpp", missing, map[string]string{}},
		{"reranker", controller, map[string]string{}},
		{"reranker", worker, map[string]string{}},
		{"reranker", missing, map[string]string{}},
	}
	for _, tc := range cases {
		got := pkiMountsOf(t, tc.backend, tc.dir)
		if len(got) != len(tc.want) {
			t.Errorf("%s in %s: PKI mounts %v, want %v", tc.backend, filepath.Base(tc.dir), got, tc.want)
		}
		for target, rel := range tc.want {
			if got[target] != filepath.Join(tc.dir, rel) {
				t.Errorf("%s in %s: %s mounted from %q, want %q", tc.backend, filepath.Base(tc.dir), target, got[target], filepath.Join(tc.dir, rel))
			}
		}
		// The two things no backend may ever hold: the PKI root (ca.key,
		// signing.key, every node's key) and any nodes/ leaf.
		for target, src := range got {
			if src == tc.dir {
				t.Errorf("%s in %s: %s is the whole PKI directory", tc.backend, filepath.Base(tc.dir), target)
			}
			if strings.Contains(src, "/nodes/") || strings.Contains(target, "/nodes/") {
				t.Errorf("%s in %s: mounts a node identity: %s -> %s", tc.backend, filepath.Base(tc.dir), src, target)
			}
		}
	}
}

// A spec must never carry a whole-directory PKI bind again, whatever the
// directory holds — the test above would still pass on a spec that mounts
// the root under a target it does not check.
func TestNoSpecMountsThePKIRoot(t *testing.T) {
	for name, spec := range backendSpecs {
		for _, v := range spec.Volumes {
			if strings.Contains(v.Source, "NOO_PKI_DIR") && strings.HasSuffix(v.Source, "}") {
				t.Errorf("%s: volume %q mounts the whole PKI directory at %s", name, v.Source, v.Target)
			}
			if strings.HasPrefix(v.Target, "/app/pki") && !v.Optional {
				t.Errorf("%s: PKI mount %s must be Optional — a node without it would fail the start on a strict bind", name, v.Target)
			}
		}
	}
	for _, v := range rerankerSpecLlamacpp().Volumes {
		if strings.Contains(v.Source, "NOO_PKI_DIR") {
			t.Errorf("reranker: mounts PKI (%q) though rerankEntrypointScript reads none", v.Source)
		}
	}
}

// An Optional mount whose host source is missing is skipped AND reported;
// a required one is passed through for Docker to fail loudly on.
func TestBuildMounts_OptionalSkipsMissingSourceAndSaysSo(t *testing.T) {
	present := t.TempDir()
	absent := filepath.Join(present, "nope")
	mounts, skipped := buildMounts([]VolumeMount{
		{Source: present, Target: "/a", Optional: true},
		{Source: absent, Target: "/b", Optional: true},
		{Source: absent, Target: "/c"},
	})
	targets := []string{}
	for _, m := range mounts {
		targets = append(targets, m.Target)
	}
	if strings.Join(targets, ",") != "/a,/c" {
		t.Errorf("mounts %v, want /a (present) and /c (required, left for Docker)", targets)
	}
	if len(skipped) != 1 || skipped[0].Target != "/b" || skipped[0].Source != absent || !strings.Contains(skipped[0].Reason, "missing") {
		t.Errorf("skipped %+v, want the one optional miss with its reason", skipped)
	}
}

// Every backend the agent dials with a client certificate is refused a
// start unless this node holds the leaf its door serves with — vLLM's own
// (services/vllm), a sidecar's (services/<sidecar>) — and that leaf names
// the host the agent dials. A provisioned node holds ca.crt + its node cert
// only, so on it every fronted backend is refused until the leaf arrives;
// the refusal is recorded (the heartbeat carries reconcile_refusals; `noo
// cluster verify` shows the row) and clears once the leaf is there.
func TestBackendDoorCheck(t *testing.T) {
	controller := writePKIDir(t, "controller")
	worker := writePKIDir(t, "worker")
	wrongSAN := writePKIDir(t, "controller-wrong-san")
	defer refusals.Reset()

	recorded := func(backend string) bool {
		for _, r := range refusals.List() {
			if r.Scope == "backend_tls" && r.Target == backend {
				return true
			}
		}
		return false
	}
	mountsFor := func(backend string) []mount.Mount {
		m, _ := buildMounts(backendSpecs[backend].Volumes)
		return m
	}
	fronted := []string{"vllm", "llamacpp", "ollama", "embedding", "reranker"}

	// The controller's PKI shape: every leaf, every door name → allowed.
	t.Setenv("NOO_PKI_DIR", controller)
	for _, b := range fronted {
		if err := backendDoorCheck(b, mountsFor(b)); err != nil {
			t.Errorf("%s with its leaf present: unexpected refusal %v", b, err)
		}
		if recorded(b) {
			t.Errorf("%s: an allowed start must leave no refusal row", b)
		}
	}
	// airllm: plain by named exception, never checked.
	if err := backendDoorCheck("airllm", nil); err != nil {
		t.Errorf("airllm: %v", err)
	}

	// A provisioned worker: no services/ tree → every fronted backend refused,
	// naming the leaf and the provision re-run that delivers it.
	t.Setenv("NOO_PKI_DIR", worker)
	for _, b := range fronted {
		err := backendDoorCheck(b, mountsFor(b))
		if err == nil {
			t.Fatalf("%s on a node without its leaf must be refused", b)
		}
		leaf := doorLeafService(b)
		for _, needle := range []string{"services/" + leaf, "svc-" + leaf + ".crt", "noo cluster provision", "refusing to start " + b} {
			if !strings.Contains(err.Error(), needle) {
				t.Errorf("%s: refusal must say %q: %v", b, needle, err)
			}
		}
		if !recorded(b) {
			t.Errorf("%s: the refusal must be recorded for the heartbeat", b)
		}
	}
	// Fixed (leaf delivered) → the standing refusal clears.
	t.Setenv("NOO_PKI_DIR", controller)
	for _, b := range fronted {
		if err := backendDoorCheck(b, mountsFor(b)); err != nil {
			t.Errorf("%s after the leaf arrived: %v", b, err)
		}
		if recorded(b) {
			t.Errorf("%s: a cleared refusal must not linger", b)
		}
	}

	// A leaf that does not name the door: refused, naming the SAN wanted.
	t.Setenv("NOO_PKI_DIR", wrongSAN)
	for _, b := range fronted {
		err := backendDoorCheck(b, mountsFor(b))
		want := doorDialHost(b)
		if err == nil || !strings.Contains(err.Error(), "does not name "+want) {
			t.Errorf("%s: a leaf without the %s SAN must be refused: %v", b, want, err)
		}
	}

	// No PKI dir at all: refused before anything is looked up.
	t.Setenv("NOO_PKI_DIR", "")
	if err := backendDoorCheck("vllm", nil); err == nil || !strings.Contains(err.Error(), "NOO_PKI_DIR") {
		t.Errorf("unset NOO_PKI_DIR must be refused by name: %v", err)
	}
}

// The agent-started vLLM sits behind its door (door generation 5): the
// engine listens plain on 127.0.0.1 inside noo-stunnel-vllm's namespace,
// and the door keeps the name every caller dials (noo-vllm) as its bridge
// alias, so neither the URL nor the leaf moves.
func TestVLLMServesPlainInsideItsDoor(t *testing.T) {
	code := ""
	for _, l := range strings.Split(vllmEntrypointScript, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			code += l + "\n"
		}
	}
	if !strings.Contains(code, "--host 127.0.0.1 --port 8000") || strings.Contains(code, "0.0.0.0") {
		t.Error("vllmEntrypointScript must bind 127.0.0.1:8000 only: its door connects to loopback")
	}
	if strings.Contains(code, "--ssl-") || strings.Contains(code, "NOO_VLLM_TLS") {
		t.Error("vllmEntrypointScript serves TLS again: the door holds the leaf and connects plain")
	}
	if _, ok := backendSpecs["vllm"].Env["NOO_VLLM_TLS"]; ok {
		t.Error("the vllm spec still passes NOO_VLLM_TLS into the container")
	}
	if hc := backendSpecs["vllm"].HealthcheckCmd; !strings.Contains(hc, "http://127.0.0.1:8000/health") {
		t.Errorf("the vllm healthcheck must probe the plain loopback listener: %s", hc)
	}
	if got := DoorNetworkMode("vllm"); got != "container:noo-stunnel-vllm" {
		t.Errorf("vllm network mode %q, want its door's namespace", got)
	}
	if doorDialHost("vllm") != "noo-vllm" || doorLeafService("vllm") != "vllm" {
		t.Errorf("vllm's door is dialled as %q with leaf %q: the URL and the leaf must not move", doorDialHost("vllm"), doorLeafService("vllm"))
	}
}

// The sidecar spec: one shape per fronted backend, `verify = 2`, the
// backend's leaf, the compose door port, forwarding to the backend
// container's own port; the image order tries a built stunnel before the
// alpine fallback; no host port is ever published.
func TestSidecarSpec(t *testing.T) {
	conf := stunnelConf("llamacpp", "noo-stunnel-llamacpp", 8085, 8085, "awolf")
	for _, needle := range []string{
		"verify = 2", "accept = noo-stunnel-llamacpp:8085", "connect = 127.0.0.1:8085",
		"cert = /tls/services/llamacpp/service.crt", "key = /tls/services/llamacpp/service.key",
		"CAfile = /tls/ca.crt", "foreground = yes",
	} {
		if !strings.Contains(conf, needle) {
			t.Errorf("stunnel conf lacks %q:\n%s", needle, conf)
		}
	}
	// Every fronted backend has a sidecar name, a door port and a leaf.
	for _, b := range []string{"vllm", "llamacpp", "ollama", "embedding", "reranker"} {
		if SidecarFor(b) == "" || SidecarContainerFor(b) != StunnelContainerPrefix+SidecarFor(b) || DoorPort(b) == 0 {
			t.Errorf("%s: sidecar %q container %q port %d", b, SidecarFor(b), SidecarContainerFor(b), DoorPort(b))
		}
	}
	if SidecarFor("airllm") != "" {
		t.Error("airllm is plain by exception; it gets no sidecar")
	}
	// Door ports are the compose sidecars' accept ports, so one URL reaches
	// a compose door and an agent-run one.
	for b, want := range map[string]int{"llamacpp": 8085, "ollama": 11434, "embedding": 443, "reranker": 443, "vllm": 8000} {
		if got := DoorPort(b); got != want {
			t.Errorf("%s door port %d, want %d", b, got, want)
		}
	}
	// Connect port: placement PORT wins, then the spec's, then the engine.
	if got := sidecarConnectPort("llamacpp", backendSpecs["llamacpp"], map[string]string{"PORT": "9001"}); got != 9001 {
		t.Errorf("placement PORT: %d", got)
	}
	t.Setenv("LLAMACPP_PORT", "")
	if got := sidecarConnectPort("llamacpp", backendSpecs["llamacpp"], nil); got != 8085 {
		t.Errorf("spec PORT: %d", got)
	}
	if got := sidecarConnectPort("reranker", rerankerSpecTEI(), nil); got != 80 {
		t.Errorf("TEI reranker listens on 80: %d", got)
	}
	if got := sidecarConnectPort("reranker", rerankerSpecLlamacpp(), nil); got != 8085 {
		t.Errorf("llama.cpp reranker listens on 8085: %d", got)
	}
	if got := sidecarConnectPort("ollama", backendSpecs["ollama"], nil); got != 11434 {
		t.Errorf("ollama: %d", got)
	}
	// Image order.
	t.Setenv(StunnelImageEnv, "")
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/x/noomesh")
	t.Setenv("NOO_IMAGE_TAG", "v9")
	got := strings.Join(stunnelImageCandidates("llamacpp"), ",")
	if got != "ghcr.io/x/noomesh/stunnel:v9,noomesh/stunnel:latest,"+stunnelFallbackImage {
		t.Errorf("image candidates: %s", got)
	}
	t.Setenv(StunnelImageEnv, "my/stunnel:1")
	if c := stunnelImageCandidates("llamacpp"); c[0] != "my/stunnel:1" {
		t.Errorf("override must come first: %v", c)
	}
	// The sidecar script installs stunnel only when the image lacks it.
	if !strings.Contains(stunnelSidecarScript, "exec stunnel") || !strings.Contains(stunnelSidecarScript, "apk add") {
		t.Error("sidecar script shape")
	}
	// A sidecar name reads back to its backend; compose's tei-gpu too.
	for name, want := range map[string]string{
		"noo-stunnel-llamacpp": "llamacpp", "noo-stunnel-ollama": "ollama", "noo-stunnel-tei": "embedding",
		"noo-stunnel-tei-gpu": "embedding", "noo-stunnel-reranker": "reranker", "noo-llamacpp": "", "noo-stunnel-nats": "",
	} {
		if got := sidecarBackend(name); got != want {
			t.Errorf("sidecarBackend(%q) = %q, want %q", name, got, want)
		}
	}
	// No spec publishes a host port (there is no field for it — pin that).
	src, err := os.ReadFile("backends.go")
	if err == nil {
		if strings.Contains(string(src), "PortBindings") || strings.Contains(string(src), "PublishAllPorts") {
			t.Error("backends.go publishes a host port; a backend's raw port must stay on the bridge")
		}
	}
	if src, err := os.ReadFile("sidecar.go"); err == nil && strings.Contains(string(src), "PortBindings") {
		t.Error("sidecar.go publishes a host port")
	}
}

// Door generation 3 (followup 1234 F-ii): the sidecar is the ONLY door.
// The fronted engine runs in its sidecar's network namespace on loopback;
// the sidecar accepts on its own bridge address, never 0.0.0.0 (which would
// also take 127.0.0.1:<port> from an engine on the same port), and connects
// to loopback. Each failure here reopens a plaintext port to the bridge.
func TestTheSidecarIsTheOnlyDoor(t *testing.T) {
	if BackendDoorGeneration < 3 {
		t.Fatalf("BackendDoorGeneration = %d: placed backends would keep the bridge shape", BackendDoorGeneration)
	}
	for _, b := range []string{"vllm", "llamacpp", "ollama", "embedding", "reranker"} {
		if got, want := DoorNetworkMode(b), "container:"+SidecarContainerFor(b); got != want {
			t.Errorf("%s network mode %q, want %q", b, got, want)
		}
		conf := stunnelConf(SidecarFor(b), SidecarContainerFor(b), DoorPort(b), 1234, "awolf")
		if strings.Contains(conf, "0.0.0.0") || !strings.Contains(conf, "accept = "+SidecarContainerFor(b)+":") ||
			!strings.Contains(conf, "connect = 127.0.0.1:1234") {
			t.Errorf("%s conf:\n%s", b, conf)
		}
	}
	if DoorNetworkMode("airllm") != "" {
		t.Error("only a fronted backend joins a sidecar's namespace")
	}
	// Every engine's bind knob, pinned to loopback with the connect port.
	env := privateDoorEnv(11434)
	for k, want := range map[string]string{
		"HOST": "127.0.0.1", "LLAMA_ARG_HOST": "127.0.0.1", "LLAMA_ARG_PORT": "11434",
		"OLLAMA_HOST": "127.0.0.1:11434", "HOSTNAME": "127.0.0.1",
	} {
		if env[k] != want {
			t.Errorf("privateDoorEnv[%s] = %q, want %q", k, env[k], want)
		}
	}

	src, err := os.ReadFile("backends.go")
	if err != nil {
		t.Skip("source not readable from the test dir")
	}
	body := string(src)
	start := strings.Index(body, "func (c *Client) StartBackendSDK(")
	end := strings.Index(body, "func (c *Client) StopBackendSDK(")
	if start < 0 || end < start {
		t.Fatal("StartBackendSDK not found")
	}
	fn := body[start:end]
	// The loopback env goes on after the placement's ExtraEnv, so no
	// placement can put the engine back on the bridge.
	if i, j := strings.Index(fn, "overrides.ExtraEnv"), strings.Index(fn, "privateDoorEnv("); i < 0 || j < i {
		t.Error("privateDoorEnv must be applied after the placement's ExtraEnv")
	}
	// The namespace owner exists before the engine is created in it.
	if i, j := strings.Index(fn, "c.startSidecar("), strings.Index(fn, "c.docker.ContainerCreate("); i < 0 || j < i {
		t.Error("the sidecar must start before the engine container is created")
	}
	if !strings.Contains(fn, "hostCfg.NetworkMode = container.NetworkMode(mode)") {
		t.Error("the engine must be created in DoorNetworkMode")
	}
	if strings.Contains(body, `"0.0.0.0"`) {
		t.Error("a backend spec binds 0.0.0.0; fronted engines listen on doorLoopback")
	}
}

// judgeEngineDoor: the generation-3 rows for a fronted engine.
func TestJudgeEngineDoor(t *testing.T) {
	sidecars := map[string]string{"abc123def4567890": "noo-stunnel-llamacpp"}
	early, late := "2026-10-28T10:00:00.000000001Z", "2026-10-28T10:05:00Z"
	for _, tc := range []struct {
		name, mode, eng, sc string
		want                engineDoorShape
	}{
		{"bridge (pre-generation-3)", "noo-cluster", early, late, engineOnBridge},
		{"default bridge", "", "", "", engineOnBridge},
		{"in its door, by id", "container:abc123def4567890", late, early, engineInDoor},
		{"in its door, by name", "container:noo-stunnel-llamacpp", late, early, engineInDoor},
		{"in its door, short id", "container:abc123def456", late, early, engineInDoor},
		{"start times unknown", "container:abc123def4567890", "", "", engineInDoor},
		{"sidecar restarted after the engine", "container:abc123def4567890", early, late, engineStranded},
		{"namespace owner gone", "container:ffffffffffff", late, early, engineStranded},
	} {
		if got, _ := judgeEngineDoor(tc.mode, sidecars, tc.eng, tc.sc); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The llama.cpp image's own HEALTHCHECK hardcodes :8080, but the cluster
// runs the server on LLAMACPP_PORT (8085 by default). Without an override
// the container reports "unhealthy" forever while serving fine — observed
// on host9 as 31,841 consecutive failed probes over 11 days.
func TestLlamacppHealthcheckTargetsConfiguredPort(t *testing.T) {
	spec, ok := backendSpecs["llamacpp"]
	if !ok {
		t.Fatal("llamacpp spec missing")
	}
	if spec.HealthcheckURL == "" {
		t.Fatal("llamacpp must override the image healthcheck")
	}

	// The probe URL and the server port must resolve to the SAME value —
	// that agreement is the entire point, so assert it rather than the
	// literal string.
	port := resolveEnv(spec.Env["PORT"])
	url := resolveEnv(spec.HealthcheckURL)
	if port == "" {
		t.Fatal("llamacpp PORT env is empty")
	}
	if !strings.Contains(url, ":"+port+"/") {
		t.Errorf("healthcheck %q does not target the configured port %q", url, port)
	}
	if strings.Contains(url, ":8080/") && port != "8080" {
		t.Errorf("healthcheck still targets the image default 8080 while PORT=%s", port)
	}
}

// A non-default LLAMACPP_PORT must move BOTH the server and the probe, or
// the override just relocates the bug.
func TestLlamacppHealthcheckFollowsPortOverride(t *testing.T) {
	t.Setenv("LLAMACPP_PORT", "9099")
	spec := backendSpecs["llamacpp"]
	port := resolveEnv(spec.Env["PORT"])
	url := resolveEnv(spec.HealthcheckURL)
	if port != "9099" {
		t.Fatalf("PORT = %q, want 9099", port)
	}
	if !strings.Contains(url, ":9099/") {
		t.Errorf("healthcheck %q did not follow LLAMACPP_PORT override", url)
	}
}

// Backends without an explicit override keep their image's healthcheck —
// this change must not silently alter every other backend.
func TestOtherBackendsKeepImageHealthcheck(t *testing.T) {
	for name, spec := range backendSpecs {
		if name == "llamacpp" {
			continue
		}
		if spec.HealthcheckURL != "" {
			t.Errorf("%s unexpectedly overrides its image healthcheck (%q)",
				name, spec.HealthcheckURL)
		}
	}
}

// The x86 default was a LOCAL build name, so a --dist install could never
// start llamacpp on an x86 node: nothing builds `pai-assistant/llamacpp` on
// a released install and nothing published it, so the pull failed with
// "pull access denied". ARM was unaffected — it
// already resolves to the upstream multi-arch image.
func TestLlamacppImagePrefersThePublishedRelease(t *testing.T) {
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	t.Setenv("NOO_IMAGE_TAG", "v0.2.21")
	if got := llamacppDefaultImage(); got != "ghcr.io/noomesh/llamacpp:v0.2.21" {
		t.Errorf("dist install should use the published image, got %q", got)
	}
}

// A box with no release pin and no local hardened build (the hardened
// build ships in the release, but an unpinned box has not pulled it — see
// docker/README-llamacpp.md) must resolve to upstream, not to a local
// build name that only exists on a machine that built it — that mismatch
// used to fail with "pull access denied". A present
// local build still wins via the separate ImageInspect preference check
// elsewhere in this package; this function only picks the DEFAULT.
func TestLlamacppImageFallsBackToUpstreamWithNoPinAndNoLocalBuild(t *testing.T) {
	t.Setenv("NOO_IMAGE_PREFIX", "")
	t.Setenv("NOO_IMAGE_TAG", "")
	if got := llamacppDefaultImage(); got != "ghcr.io/ggml-org/llama.cpp:server" {
		t.Errorf("no pin, no local build should fall back to upstream, got %q", got)
	}
}

// The agent-started door runs as root EXPLICITLY (i132): the published
// stunnel image ends `USER 65532`, but the node's leaf under /etc/noo/pki is
// root-owned 0600 and read through DAC_OVERRIDE, and the alpine fallback's
// entrypoint runs `apk add`. A node that pulled the new image without this
// would start a door that cannot read its own key.
func TestSidecarRunsAsRootWhateverTheImageUserSays(t *testing.T) {
	if sidecarUser != "0" {
		t.Fatalf("sidecarUser = %q, want \"0\"", sidecarUser)
	}
	src, err := os.ReadFile("sidecar.go")
	if err != nil {
		t.Skip("source not readable from the test dir")
	}
	body := string(src)
	i := strings.Index(body, "cfg := &container.Config{")
	if i < 0 {
		t.Fatal("startSidecar's container.Config not found")
	}
	cfg := body[i : i+strings.Index(body[i:], "}\n")]
	if !strings.Contains(cfg, "User:") || !strings.Contains(cfg, "sidecarUser") {
		t.Errorf("startSidecar does not set User: sidecarUser on the door's container config:\n%s", cfg)
	}
}

// A backend door admits its callers by name, not any cluster-CA leaf
// (i301, internal#300): this node's own agent leaf (its node id, the leaf's
// first DNS SAN) and the controller's service callers, as the compose doors
// do. A conf without checkHost lets another node's leaf, an add-on's or a
// backend's open the door.
func TestTheDoorAdmitsNamedCallersOnly(t *testing.T) {
	if BackendDoorGeneration < 4 {
		t.Fatalf("BackendDoorGeneration = %d: a door started unpinned would never be recreated", BackendDoorGeneration)
	}
	for _, b := range []string{"llamacpp", "ollama", "embedding", "reranker"} {
		conf := stunnelConf(SidecarFor(b), SidecarContainerFor(b), DoorPort(b), 1234, "awolf")
		var pins []string
		for _, l := range strings.Split(conf, "\n") {
			if v, ok := strings.CutPrefix(l, "checkHost = "); ok {
				pins = append(pins, v)
			}
		}
		want := []string{"awolf", "gateway", "worker", "trellion", "trellion-intel", "evolve"}
		if strings.Join(pins, ",") != strings.Join(want, ",") {
			t.Errorf("%s pins %v, want %v:\n%s", b, pins, want, conf)
		}
		if !strings.Contains(conf, "verify = 2") {
			t.Errorf("%s: no client certificate required:\n%s", b, conf)
		}
	}
	// The compose doors admit the same service callers (the controller's
	// own agent is appended there by the stunnel-self-pin entrypoint).
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docker", "stunnel-llamacpp.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range doorCallers {
		if !strings.Contains(string(raw), "checkHost = "+n+"\n") {
			t.Errorf("docker/stunnel-llamacpp.conf does not admit %q, the agent's doors do", n)
		}
	}
}

// The self pin is read from the leaf the agent presents: its first DNS SAN.
// A leaf that names a shared SAN first, or no leaf at all, is refused: the
// door is not started open.
func TestDoorSelfNameReadsTheAgentLeaf(t *testing.T) {
	dir := t.TempDir()
	write := func(sans []string) string {
		crt, _ := selfSignedLeaf(t, sans)
		p := filepath.Join(dir, sans[0]+".crt")
		if err := os.WriteFile(p, crt, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("NOO_TLS_CERT", write([]string{"robopi", "localhost", "node-agent"}))
	if got, err := doorSelfName(); err != nil || got != "robopi" {
		t.Fatalf("doorSelfName() = %q, %v; want robopi", got, err)
	}
	t.Setenv("NOO_TLS_CERT", write([]string{"localhost", "node-agent"}))
	if _, err := doorSelfName(); err == nil {
		t.Error("a leaf naming localhost first must not become the pin (every node leaf carries it)")
	}
	t.Setenv("NOO_TLS_CERT", "")
	if _, err := doorSelfName(); err == nil {
		t.Error("no leaf: the door must refuse, not start unpinned")
	}
	if _, err := checkDoorPin("a\nverify = 0"); err == nil {
		t.Error("a name that breaks its conf line must be refused")
	}
}

// The backend privilege floor (i301, internal#300): beside no-new-privileges
// and CapDrop ALL, an image whose write set was measured empty runs on a
// read-only root with a tmpfs /tmp. llama-server (llamacpp and the reranker)
// and every door sidecar on the published stunnel image take it; the alpine
// fallback door cannot (its entrypoint runs `apk add`).
func TestReadOnlyRootFloor(t *testing.T) {
	if !backendSpecs["llamacpp"].ReadOnlyRoot || !rerankerSpecLlamacpp().ReadOnlyRoot {
		t.Error("llama-server writes nothing outside its read-only /models: llamacpp and the reranker take a read-only root")
	}
	for _, b := range []string{"vllm", "ollama", "embedding"} {
		if backendSpecs[b].ReadOnlyRoot {
			t.Errorf("%s writes caches into its image paths; a read-only root needs its write set measured first", b)
		}
	}
	h := &container.HostConfig{}
	rootFloor(h, true)
	if !h.ReadonlyRootfs || h.Tmpfs["/tmp"] == "" || !strings.Contains(h.Tmpfs["/tmp"], "noexec") {
		t.Errorf("rootFloor(true) = ro %v tmpfs %v", h.ReadonlyRootfs, h.Tmpfs)
	}
	h = &container.HostConfig{}
	rootFloor(h, false)
	if h.ReadonlyRootfs || h.Tmpfs != nil {
		t.Errorf("rootFloor(false) changed the config: ro %v tmpfs %v", h.ReadonlyRootfs, h.Tmpfs)
	}
	// Both create paths apply it.
	for file, call := range map[string]string{
		"backends.go": "rootFloor(hostCfg, spec.ReadOnlyRoot)",
		"sidecar.go":  "rootFloor(hostCfg, image != stunnelFallbackImage)",
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), call) {
			t.Errorf("%s does not call %s", file, call)
		}
	}
}
