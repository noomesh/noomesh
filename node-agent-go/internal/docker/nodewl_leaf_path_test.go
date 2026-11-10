package docker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// The door leaf's two halves, the applier that installs it (noo-apply.sh)
// and the agent that looks for it (checkLeaf), were never run together: no
// leaf was delivered until 0.6.21, and on the first live node the agent
// refused a leaf the applier had installed (it read the bundle's flat
// svc-addon-<a>-<w>.crt name in the PKI dir). These tests hold the agent to
// the applier's layout.

func leafEntry() nodewl.Entry {
	return nodewl.Entry{Addon: "rhaddon", Name: "worker", Door: &nodewl.Door{Leaf: "svc-addon-rhaddon-worker"}}
}

func leafPKI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("ca"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The applier's add-on loop installs into $PKI/services/$_asvc, where $_asvc
// is the bundle file name without "svc-" and without its extension, as
// service.crt (0644) and service.key (0600), root-owned. Read from the script
// itself, so a change on either side fails here.
func TestTheAgentLooksWhereNooApplyInstallsTheAddonLeaf(t *testing.T) {
	raw, err := os.ReadFile("../../../scripts/noo-apply.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	i := strings.Index(src, "svc-addon-<addon>-<workload>.crt|.key")
	if i < 0 {
		t.Fatal("noo-apply.sh no longer has the add-on door leaf block this test reads")
	}
	block := src[i:]
	if j := strings.Index(block, "\ndone\n"); j > 0 {
		block = block[:j]
	}
	for _, want := range []string{
		`_ab="${_ab#svc-}"; echo "${_ab%.*}"`,
		`_d="$PKI/services/$_asvc"`,
		`install -m 600 -o root -g root "$_k" "$_d/.service.key.next"`,
		`install -m 644 -o root -g root "$_c" "$_d/.service.crt.next"`,
		`mv -f "$_d/.service.key.next" "$_d/service.key"`,
		`mv -f "$_d/.service.crt.next" "$_d/service.crt"`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the applier's add-on leaf block no longer has %q", want)
		}
	}
	// The applier's name transform, applied to the bundle name the gateway
	// gives this entry, must be the agent's directory.
	e := leafEntry()
	asvc := strings.TrimPrefix(e.Door.Leaf, "svc-")
	if got, want := addonLeafDir("/pki", e.Addon, e.Name), filepath.Join("/pki", "services", asvc); got != want {
		t.Fatalf("agent dir %s, applier dir %s", got, want)
	}
}

// (1) A tree laid out exactly as the applier installs it is accepted, and the
// door container is handed those exact files.
func TestCheckLeafAcceptsTheTreeTheApplierInstalls(t *testing.T) {
	pki := leafPKI(t)
	writeLeaf(t, pki, "svc-addon-rhaddon-worker", "noo-stunnel-rhaddon-worker")
	d := filepath.Join(pki, "services", "addon-rhaddon-worker")
	for f, mode := range map[string]os.FileMode{"service.crt": 0o644, "service.key": 0o600} {
		fi, err := os.Stat(filepath.Join(d, f))
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("fixture %s: %v %v (want %o, the applier's mode)", f, err, fi, mode)
		}
	}
	p := &NodeWorkloads{PKIDir: func() string { return pki }}
	lf, err := p.checkLeaf(leafEntry())
	if err != nil {
		t.Fatalf("the applier's layout was refused: %v", err)
	}
	if lf.crt != filepath.Join(d, "service.crt") || lf.key != filepath.Join(d, "service.key") || lf.ca != filepath.Join(pki, "ca.crt") {
		t.Fatalf("leaf files %+v", lf)
	}
	if lf.print == "" {
		t.Fatal("no fingerprint")
	}
}

// (2) The bundle's flat name in the PKI directory is not where the applier
// puts the leaf; finding only that is door_leaf_missing, naming the
// installed path.
func TestCheckLeafDoesNotAcceptTheFlatBundleName(t *testing.T) {
	pki := leafPKI(t)
	for _, ext := range []string{".crt", ".key"} {
		if err := os.WriteFile(filepath.Join(pki, "svc-addon-rhaddon-worker"+ext), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := &NodeWorkloads{PKIDir: func() string { return pki }}
	_, err := p.checkLeaf(leafEntry())
	if nodewl.CodeOf(err) != nodewl.ReasonDoorLeafMissing {
		t.Fatalf("a flat svc-addon-*.crt alone was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), filepath.Join("services", "addon-rhaddon-worker", "service.crt")) {
		t.Fatalf("the refusal must name the installed path: %v", err)
	}
}

// (3) A leaf in the right place that names another door is still refused.
func TestCheckLeafRefusesALeafNamingAnotherDoor(t *testing.T) {
	pki := leafPKI(t)
	writeLeaf(t, pki, "svc-addon-rhaddon-worker", "noo-stunnel-other-worker")
	p := &NodeWorkloads{PKIDir: func() string { return pki }}
	_, err := p.checkLeaf(leafEntry())
	if nodewl.CodeOf(err) != nodewl.ReasonDoorLeafMissing || !strings.Contains(err.Error(), "does not name noo-stunnel-rhaddon-worker") {
		t.Fatalf("a leaf naming another door was not refused as such: %v", err)
	}
}

// The key must be there too: a crt alone in the installed directory is
// door_leaf_missing (the door container cannot start without its key).
func TestCheckLeafRefusesACertWithoutItsKey(t *testing.T) {
	pki := leafPKI(t)
	writeLeaf(t, pki, "svc-addon-rhaddon-worker", "noo-stunnel-rhaddon-worker")
	_ = os.Remove(filepath.Join(pki, "services", "addon-rhaddon-worker", "service.key"))
	p := &NodeWorkloads{PKIDir: func() string { return pki }}
	_, err := p.checkLeaf(leafEntry())
	if nodewl.CodeOf(err) != nodewl.ReasonDoorLeafMissing || !strings.Contains(err.Error(), "service.key") {
		t.Fatalf("a missing key was not refused: %v", err)
	}
}
