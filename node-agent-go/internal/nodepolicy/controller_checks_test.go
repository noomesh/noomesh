// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// i596: the controller's signed approval set. SECURITY code, so each test
// below pins ONE check and fails when that check alone is removed.

const testNode = "n1"

type signer struct {
	priv    *ecdsa.PrivateKey
	pubPath string
}

// newSigner makes a fleet signing key (ECDSA P-384) and writes its public
// half as SPKI PEM, the way /etc/noo/pki/signing.pub is.
func newSigner(t *testing.T) *signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "signing.pub")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return &signer{priv: priv, pubPath: p}
}

func (s *signer) sign(t *testing.T, doc []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(doc)
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// setDoc is the canonical document the controller CLI signs.
func setDoc(t *testing.T, node string, gen int64, approvals ...Approval) []byte {
	t.Helper()
	if approvals == nil {
		approvals = []Approval{}
	}
	b, err := json.Marshal(ControllerSet{Kind: ControllerSetKind, Node: node, Generation: gen, IssuedAt: "2026-11-08T12:00:00Z", Approvals: approvals})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ctlFor is a ControllerApprovals in a fresh state dir; optIn writes the
// owner's opt-in as this test's user and makes that user stand in for root.
func ctlFor(t *testing.T, s *signer, optIn bool) *ControllerApprovals {
	t.Helper()
	dir := t.TempDir()
	c := NewControllerApprovals(dir, testNode, s.pubPath)
	c.optInUID = uint32(os.Getuid())
	if optIn {
		writeOptIn(t, dir, 0o644)
	}
	return c
}

func writeOptIn(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, OptInFile)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func verify(t *testing.T, s *signer, doc, sig []byte) error {
	t.Helper()
	pub, err := (&ControllerApprovals{pubPath: s.pubPath}).key()
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyControllerSet(pub, testNode, doc, sig)
	return err
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v; want %v", err, want)
	}
}

var apA = Approval{Addon: "rhaddon", Digest: digestA}

// ---- VerifyControllerSet: one check each ---------------------------------

func TestAControllerSetSignedByAnotherKeyIsRefused(t *testing.T) {
	s, other := newSigner(t), newSigner(t)
	doc := setDoc(t, testNode, 1, apA)
	wantErr(t, verify(t, s, doc, other.sign(t, doc)), ErrSetSignature)
	wantErr(t, verify(t, s, doc, []byte("not a signature")), ErrSetSignature)
}

func TestASignatureOverOtherBytesOfTheSameSetIsRefused(t *testing.T) {
	s := newSigner(t)
	doc := setDoc(t, testNode, 1, apA)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, doc, "", "  "); err != nil {
		t.Fatal(err)
	}
	// The same set, re-serialised: the signature covers bytes, not meaning.
	wantErr(t, verify(t, s, pretty.Bytes(), s.sign(t, doc)), ErrSetSignature)
	wantErr(t, verify(t, s, doc, s.sign(t, pretty.Bytes())), ErrSetSignature)
}

func TestAControllerSetOfAnotherKindIsRefused(t *testing.T) {
	s := newSigner(t)
	doc := bytes.Replace(setDoc(t, testNode, 1, apA), []byte(ControllerSetKind), []byte("noomesh.node-workload-approvals/v2"), 1)
	wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetKind)
}

func TestAControllerSetForAnotherNodeIsRefused(t *testing.T) {
	s := newSigner(t)
	for _, node := range []string{"n2", "n10", "N1", "n", ""} {
		doc := setDoc(t, node, 1, apA)
		wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetNode)
	}
	// A node with no id binds nothing, even a set that names no node.
	doc := setDoc(t, "", 1, apA)
	pub, _ := (&ControllerApprovals{pubPath: s.pubPath}).key()
	if _, err := VerifyControllerSet(pub, "", doc, s.sign(t, doc)); !errors.Is(err, ErrSetNode) {
		t.Fatalf("an empty self id: %v", err)
	}
}

func TestAControllerSetBelowGenerationOneIsRefused(t *testing.T) {
	s := newSigner(t)
	for _, gen := range []int64{0, -1} {
		doc := setDoc(t, testNode, gen, apA)
		wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetGeneration)
	}
}

func TestAControllerSetWithABadIssuedAtIsRefused(t *testing.T) {
	s := newSigner(t)
	doc := bytes.Replace(setDoc(t, testNode, 1, apA), []byte("2026-11-08T12:00:00Z"), []byte("yesterday"), 1)
	wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetIssuedAt)
}

func TestAControllerSetWithAnUnknownFieldIsRefused(t *testing.T) {
	s := newSigner(t)
	for _, doc := range [][]byte{
		bytes.Replace(setDoc(t, testNode, 1, apA), []byte(`"generation"`), []byte(`"pattern":"*","generation"`), 1),
		bytes.Replace(setDoc(t, testNode, 1, apA), []byte(`"addon"`), []byte(`"any":true,"addon"`), 1),
	} {
		wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetDecode)
	}
}

func TestAControllerSetWithDataAfterItIsRefused(t *testing.T) {
	s := newSigner(t)
	doc := append(setDoc(t, testNode, 1, apA), setDoc(t, testNode, 2)...)
	err := verify(t, s, doc, s.sign(t, doc))
	wantErr(t, err, ErrSetDecode)
	if !strings.Contains(err.Error(), "data after") {
		t.Fatalf("refused, but not for the trailing value: %v", err)
	}
}

func TestAControllerSetWithoutAnApprovalsListIsRefused(t *testing.T) {
	s := newSigner(t)
	for _, doc := range [][]byte{
		bytes.Replace(setDoc(t, testNode, 1), []byte(`"approvals":[]`), []byte(`"approvals":null`), 1),
		bytes.Replace(setDoc(t, testNode, 1), []byte(`,"approvals":[]`), nil, 1),
	} {
		wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetApprovals)
	}
}

func TestAControllerSetEntryWithABadDigestIsRefused(t *testing.T) {
	s := newSigner(t)
	for _, d := range []string{"sha256:*", "sha256:" + strings.Repeat("A", 64), digestA[:len(digestA)-1], "*", ""} {
		doc := setDoc(t, testNode, 1, Approval{Addon: "rhaddon", Digest: d})
		wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetEntry)
	}
}

func TestAControllerSetEntryWithABadAddonIsRefused(t *testing.T) {
	s := newSigner(t)
	for _, a := range []string{"*", "", "Rhaddon", "rh_addon", "-rh"} {
		doc := setDoc(t, testNode, 1, Approval{Addon: a, Digest: digestA})
		wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetEntry)
	}
}

func TestAControllerSetNamingAnEntryTwiceIsRefused(t *testing.T) {
	s := newSigner(t)
	doc := setDoc(t, testNode, 1, apA, apA)
	wantErr(t, verify(t, s, doc, s.sign(t, doc)), ErrSetDuplicate)
}

func TestAWellFormedControllerSetVerifies(t *testing.T) {
	s := newSigner(t)
	doc := setDoc(t, testNode, 3, apA, Approval{Addon: "rhaddon", Digest: digestB})
	if err := verify(t, s, doc, s.sign(t, doc)); err != nil {
		t.Fatal(err)
	}
}

// ---- domain separation: a set is never a model-set manifest, nor back -----

func TestTheModelSetParserRefusesAnApprovalsDocument(t *testing.T) {
	doc := setDoc(t, testNode, 1, apA)
	if _, err := nodewl.ParseModelSet(doc); err == nil {
		t.Fatal("a model-set manifest parser accepted a workload approvals document")
	}
}

func TestAModelSetManifestIsNotAnApprovalSet(t *testing.T) {
	s := newSigner(t)
	manifest := []byte(`{"format":"noo-model-set/1","id":"rh-stt-small","revision":"r1","kind":"voice","node":"n1","generation":1}`)
	err := verify(t, s, manifest, s.sign(t, manifest))
	if err == nil {
		t.Fatal("a signed model-set manifest verified as an approval set")
	}
}

// ---- Offer: the persisted set ---------------------------------------------

func held(t *testing.T, c *ControllerApprovals) []byte {
	t.Helper()
	b, err := os.ReadFile(c.path())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOfferPersistsANewerSetPrivatelyAndAtomically(t *testing.T) {
	s := newSigner(t)
	c := ctlFor(t, s, true)
	doc := setDoc(t, testNode, 1, apA)
	gen, changed, err := c.Offer(doc, s.sign(t, doc))
	if err != nil || !changed || gen != 1 {
		t.Fatalf("Offer = %d %v %v", gen, changed, err)
	}
	fi, err := os.Stat(c.path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(c.dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temp file was left: %s", e.Name())
		}
	}
	doc2 := setDoc(t, testNode, 2)
	if gen, changed, err := c.Offer(doc2, s.sign(t, doc2)); err != nil || !changed || gen != 2 {
		t.Fatalf("a newer set: %d %v %v", gen, changed, err)
	}
	if ok, _, _ := c.Has("rhaddon", digestA); ok {
		t.Error("generation 2 dropped the entry (a revoke), and it still admits")
	}
}

func TestOfferRefusesAnOlderGeneration(t *testing.T) {
	s := newSigner(t)
	c := ctlFor(t, s, true)
	d2 := setDoc(t, testNode, 2)
	if _, _, err := c.Offer(d2, s.sign(t, d2)); err != nil {
		t.Fatal(err)
	}
	before := held(t, c)
	d1 := setDoc(t, testNode, 1, apA)
	_, _, err := c.Offer(d1, s.sign(t, d1))
	wantErr(t, err, ErrSetRollback)
	if !bytes.Equal(held(t, c), before) {
		t.Error("a rollback changed the held set")
	}
	if ok, _, _ := c.Has("rhaddon", digestA); ok {
		t.Error("the replayed older set admits")
	}
}

func TestOfferRefusesTheHeldGenerationWithOtherBytes(t *testing.T) {
	s := newSigner(t)
	c := ctlFor(t, s, true)
	d := setDoc(t, testNode, 1)
	if _, _, err := c.Offer(d, s.sign(t, d)); err != nil {
		t.Fatal(err)
	}
	before := held(t, c)
	other := setDoc(t, testNode, 1, apA)
	_, _, err := c.Offer(other, s.sign(t, other))
	wantErr(t, err, ErrSetConflict)
	if !bytes.Equal(held(t, c), before) {
		t.Error("the conflicting set replaced the held one")
	}
}

func TestOfferOfTheHeldSetIsANoOp(t *testing.T) {
	s := newSigner(t)
	c := ctlFor(t, s, true)
	d := setDoc(t, testNode, 1, apA)
	sig := s.sign(t, d)
	if _, _, err := c.Offer(d, sig); err != nil {
		t.Fatal(err)
	}
	// ECDSA signatures differ each time; the document's bytes decide.
	if gen, changed, err := c.Offer(d, s.sign(t, d)); err != nil || changed || gen != 1 {
		t.Fatalf("the same set again: %d %v %v", gen, changed, err)
	}
}

func TestARefusedOfferKeepsTheHeldSet(t *testing.T) {
	s, other := newSigner(t), newSigner(t)
	c := ctlFor(t, s, true)
	d1 := setDoc(t, testNode, 1, apA)
	if _, _, err := c.Offer(d1, s.sign(t, d1)); err != nil {
		t.Fatal(err)
	}
	before := held(t, c)
	apB := Approval{Addon: "rhaddon", Digest: digestB}
	d2 := setDoc(t, testNode, 2, apB)
	if _, _, err := c.Offer(d2, other.sign(t, d2)); err == nil {
		t.Fatal("a set signed by another key was accepted")
	}
	if !bytes.Equal(held(t, c), before) {
		t.Error("a refused offer changed the held set")
	}
	if ok, gen, err := c.Has("rhaddon", digestA); !ok || gen != 1 || err != nil {
		t.Errorf("the held set no longer admits its entry: %v %d %v", ok, gen, err)
	}
	if ok, _, _ := c.Has("rhaddon", digestB); ok {
		t.Error("the refused set's entry admits")
	}
}

// tamper rewrites the held file's document while keeping its signature.
func tamper(t *testing.T, c *ControllerApprovals, doc []byte) {
	t.Helper()
	var w signedDoc
	if err := json.Unmarshal(held(t, c), &w); err != nil {
		t.Fatal(err)
	}
	w.Doc = base64.StdEncoding.EncodeToString(doc)
	b, _ := json.Marshal(w)
	if err := os.WriteFile(c.path(), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAHeldSetTamperedAfterItWasWrittenIsAnErrorAndTheGateRefuses(t *testing.T) {
	s := newSigner(t)
	c := ctlFor(t, s, true)
	d := setDoc(t, testNode, 1)
	if _, _, err := c.Offer(d, s.sign(t, d)); err != nil {
		t.Fatal(err)
	}
	tamper(t, c, setDoc(t, testNode, 1, apA))
	ok, _, err := c.Has("rhaddon", digestA)
	if ok || !errors.Is(err, ErrSetPersisted) {
		t.Fatalf("Has on a tampered set = %v, %v; want false and an error", ok, err)
	}
	g := &Gate{Mode: ModeApprove, Approvals: NewApprovals(t.TempDir()), Controller: c}
	if code := nodewl.CodeOf(g.Check(context.Background(), entry("rhaddon", digestA))); code != nodewl.ReasonConsentUnapproved {
		t.Errorf("the gate on a tampered set: %q", code)
	}
	// And a newer offer does not quietly paper over it.
	d2 := setDoc(t, testNode, 2, apA)
	if _, _, err := c.Offer(d2, s.sign(t, d2)); !errors.Is(err, ErrSetPersisted) {
		t.Errorf("an offer over a tampered set: %v", err)
	}
	if st := c.Status(); st["set_state"] != "unverifiable" {
		t.Errorf("status of a tampered set: %v", st)
	}
}

func TestAHeldFileThatIsNotJSONIsAnErrorNotNoSet(t *testing.T) {
	s := newSigner(t)
	c := ctlFor(t, s, true)
	if err := os.WriteFile(c.path(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Has("rhaddon", digestA); !errors.Is(err, ErrSetPersisted) {
		t.Fatalf("Has: %v", err)
	}
}

// ---- Has: exact match, and only when opted in ----------------------------

func heldWith(t *testing.T, s *signer, optIn bool, a ...Approval) *ControllerApprovals {
	t.Helper()
	c := ctlFor(t, s, optIn)
	d := setDoc(t, testNode, 1, a...)
	if _, _, err := c.Offer(d, s.sign(t, d)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheControllerSetAdmitsOnlyTheExactDigest(t *testing.T) {
	s := newSigner(t)
	c := heldWith(t, s, true, apA)
	if ok, gen, err := c.Has("rhaddon", digestA); !ok || gen != 1 || err != nil {
		t.Fatalf("the exact digest: %v %d %v", ok, gen, err)
	}
	for _, d := range []string{digestA[:len(digestA)-1], digestB, "sha256:", ""} {
		if ok, _, _ := c.Has("rhaddon", d); ok {
			t.Errorf("digest %q admitted", d)
		}
	}
}

func TestTheControllerSetAdmitsOnlyTheExactAddon(t *testing.T) {
	s := newSigner(t)
	c := heldWith(t, s, true, apA)
	for _, a := range []string{"rhaddo", "rhaddon2", "other", ""} {
		if ok, _, _ := c.Has(a, digestA); ok {
			t.Errorf("add-on %q admitted", a)
		}
	}
}

func TestWithoutTheOptInTheControllerSetIsIgnored(t *testing.T) {
	s := newSigner(t)
	c := heldWith(t, s, false, apA)
	if ok, _, err := c.Has("rhaddon", digestA); ok || err != nil {
		t.Fatalf("not opted in: %v %v; want false and no error", ok, err)
	}
	// Ignored entirely: even a held set that no longer verifies is no error.
	tamper(t, c, setDoc(t, testNode, 1))
	if ok, _, err := c.Has("rhaddon", digestA); ok || err != nil {
		t.Fatalf("not opted in, tampered: %v %v", ok, err)
	}
	g := &Gate{Mode: ModeApprove, Approvals: NewApprovals(t.TempDir()), Controller: heldWith(t, s, false, apA)}
	if code := nodewl.CodeOf(g.Check(context.Background(), entry("rhaddon", digestA))); code != nodewl.ReasonConsentUnapproved {
		t.Errorf("the gate, not opted in: %q", code)
	}
}

// ---- the opt-in file -----------------------------------------------------

func TestAnOptInThatIsASymlinkIsNotAnOptIn(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	target := writeOptIn(t, elsewhere, 0o644)
	if err := os.Symlink(target, filepath.Join(dir, OptInFile)); err != nil {
		t.Fatal(err)
	}
	if ok, err := optedIn(dir, uint32(os.Getuid())); ok || err == nil {
		t.Fatalf("a symlinked opt-in: %v %v", ok, err)
	}
}

func TestAnOptInNotOwnedByRootIsNotAnOptIn(t *testing.T) {
	dir := t.TempDir()
	writeOptIn(t, dir, 0o644)
	if ok, err := optedIn(dir, uint32(os.Getuid())+1); ok || err == nil {
		t.Fatalf("an opt-in owned by someone else: %v %v", ok, err)
	}
	if ok, err := optedIn(dir, uint32(os.Getuid())); !ok || err != nil {
		t.Fatalf("the same file owned by the expected owner: %v %v", ok, err)
	}
}

func TestAnOptInWritableByGroupOrOthersIsNotAnOptIn(t *testing.T) {
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
		dir := t.TempDir()
		writeOptIn(t, dir, mode)
		if ok, err := optedIn(dir, uint32(os.Getuid())); ok || err == nil {
			t.Errorf("mode %v: %v %v", mode, ok, err)
		}
	}
}

func TestAnOptInThatIsADirectoryIsNotAnOptIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, OptInFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, err := optedIn(dir, uint32(os.Getuid())); ok || err == nil {
		t.Fatalf("a directory: %v %v", ok, err)
	}
}

func TestNoOptInFileIsNotOptedInAndNoError(t *testing.T) {
	if ok, err := OptedIn(t.TempDir()); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
}

func TestOptedInRequiresRoot(t *testing.T) {
	dir := t.TempDir()
	writeOptIn(t, dir, 0o644)
	ok, err := OptedIn(dir)
	if os.Getuid() == 0 {
		if !ok || err != nil {
			t.Fatalf("root's own file: %v %v", ok, err)
		}
	} else if ok || err == nil {
		t.Fatalf("a file this non-root test wrote counted as root's: %v %v", ok, err)
	}
}

// ---- the gate's order ----------------------------------------------------

func TestNoneBeatsAControllerApproval(t *testing.T) {
	s := newSigner(t)
	c := heldWith(t, s, true, apA)
	for _, mode := range []Mode{ModeNone, Mode(""), Mode("yes")} {
		g := &Gate{Mode: mode, Approvals: NewApprovals(t.TempDir()), Controller: c}
		if code := nodewl.CodeOf(g.Check(context.Background(), entry("rhaddon", digestA))); code != nodewl.ReasonConsentNone {
			t.Errorf("mode %q: %q", mode, code)
		}
	}
}

func TestAnOptedInControllerApprovalAdmitsUnderApprove(t *testing.T) {
	s := newSigner(t)
	g := &Gate{Mode: ModeApprove, Approvals: NewApprovals(t.TempDir()), Controller: heldWith(t, s, true, apA)}
	if err := g.consent(entry("rhaddon", digestA)); err != nil {
		t.Fatalf("an opted-in controller approval: %v", err)
	}
	if code := nodewl.CodeOf(g.consent(entry("rhaddon", digestB))); code != nodewl.ReasonConsentUnapproved {
		t.Errorf("a digest neither approves: %q", code)
	}
	// Without a local store at all, the controller still speaks.
	g = &Gate{Mode: ModeApprove, Controller: heldWith(t, s, true, apA)}
	if err := g.consent(entry("rhaddon", digestA)); err != nil {
		t.Fatalf("no local store: %v", err)
	}
}

func TestALocalStoreThatCannotBeReadRefusesEvenWhenTheControllerApproves(t *testing.T) {
	s := newSigner(t)
	local := t.TempDir()
	if err := os.WriteFile(filepath.Join(local, ApprovalsFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: ModeApprove, Approvals: NewApprovals(local), Controller: heldWith(t, s, true, apA)}
	err := g.consent(entry("rhaddon", digestA))
	if nodewl.CodeOf(err) != nodewl.ReasonConsentUnapproved || !strings.Contains(err.Error(), "approvals file cannot be read") {
		t.Fatalf("got %v", err)
	}
}

func TestAnUnverifiableControllerSetRefusesOnlyWhatTheLocalStoreDidNot(t *testing.T) {
	s := newSigner(t)
	local := t.TempDir()
	if err := NewApprovals(local).Add("rhaddon", digestA); err != nil {
		t.Fatal(err)
	}
	c := heldWith(t, s, true, Approval{Addon: "rhaddon", Digest: digestB})
	tamper(t, c, setDoc(t, testNode, 1))
	g := &Gate{Mode: ModeApprove, Approvals: NewApprovals(local), Controller: c}
	if err := g.consent(entry("rhaddon", digestA)); err != nil {
		t.Errorf("the local approval: %v", err)
	}
	err := g.consent(entry("rhaddon", digestB))
	if nodewl.CodeOf(err) != nodewl.ReasonConsentUnapproved || !strings.Contains(err.Error(), "cannot be verified") {
		t.Errorf("the controller's entry, set unverifiable: %v", err)
	}
}

// ---- delivery ------------------------------------------------------------

func TestADeliveryIsDocAndSigInBase64AndNothingElse(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("x"))
	good := `{"doc":"` + b64 + `","sig":"` + b64 + `"}`
	if _, _, err := DecodeDelivery(json.RawMessage(good)); err != nil {
		t.Fatalf("good: %v", err)
	}
	for name, raw := range map[string]string{
		"unknown field": `{"doc":"` + b64 + `","sig":"` + b64 + `","gen":2}`,
		"doc not b64":   `{"doc":"%%%","sig":"` + b64 + `"}`,
		"sig not b64":   `{"doc":"` + b64 + `","sig":"%%%"}`,
		"empty doc":     `{"doc":"","sig":"` + b64 + `"}`,
		"empty sig":     `{"doc":"` + b64 + `","sig":""}`,
		"trailing":      good + good,
		"not an object": `[]`,
	} {
		if _, _, err := DecodeDelivery(json.RawMessage(raw)); !errors.Is(err, ErrSetDeliveryBad) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ---- the heartbeat -------------------------------------------------------

func TestTheHeartbeatReportsTheControllerSet(t *testing.T) {
	s := newSigner(t)
	c := heldWith(t, s, true, apA)
	f := &Facts{Mode: ModeApprove, Approvals: NewApprovals(t.TempDir()), Controller: c}
	out := f.Report(context.Background())
	st, ok := out["addon_workloads_controller"].(map[string]any)
	if !ok {
		t.Fatalf("no addon_workloads_controller: %v", out)
	}
	want := sha256.Sum256(setDoc(t, testNode, 1, apA))
	if st["opted_in"] != true || st["set_state"] != "verified" || st["generation"] != int64(1) || st["set_sha256"] != hex.EncodeToString(want[:]) {
		t.Errorf("status = %v", st)
	}
	b, _ := json.Marshal(out["addon_workloads_approvals"])
	if string(b) != `[{"addon":"rhaddon","digest":"`+digestA+`","source":"controller"}]` {
		t.Errorf("approvals = %s", b)
	}
}

func TestTheHeartbeatCarriesNoControllerRowsWithoutTheOptIn(t *testing.T) {
	s := newSigner(t)
	f := &Facts{Mode: ModeApprove, Approvals: NewApprovals(t.TempDir()), Controller: heldWith(t, s, false, apA)}
	out := f.Report(context.Background())
	b, _ := json.Marshal(out["addon_workloads_approvals"])
	if string(b) != `[]` {
		t.Errorf("approvals = %s", b)
	}
	st := out["addon_workloads_controller"].(map[string]any)
	if st["opted_in"] != false || st["set_state"] != "verified" {
		t.Errorf("status = %v", st)
	}
}

func TestAControllerRowTheOwnerAlsoApprovedIsReportedOnce(t *testing.T) {
	s := newSigner(t)
	local := t.TempDir()
	if err := NewApprovals(local).Add("rhaddon", digestA); err != nil {
		t.Fatal(err)
	}
	f := &Facts{Mode: ModeApprove, Approvals: NewApprovals(local), Controller: heldWith(t, s, true, apA)}
	b, _ := json.Marshal(f.Report(context.Background())["addon_workloads_approvals"])
	if string(b) != `[{"addon":"rhaddon","digest":"`+digestA+`"}]` {
		t.Errorf("approvals = %s", b)
	}
}

func TestTheHeartbeatNeverExceedsTheGatewaysCap(t *testing.T) {
	local := make([]Approval, maxReportedApprovals)
	f := &Facts{Controller: heldWith(t, newSigner(t), true, apA)}
	if got := f.withController(local).([]any); len(got) != maxReportedApprovals {
		t.Errorf("%d rows; the gateway drops more than %d", len(got), maxReportedApprovals)
	}
}
