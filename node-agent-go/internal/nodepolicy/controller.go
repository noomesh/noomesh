// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
)

// Approving a node workload from the controller (i596). The operator signs,
// with the FLEET signing key (signing.pub's private half, which the gateway
// never holds), one approval set per node:
//
//	{"kind":"noomesh.node-workload-approvals/v1","node":"<id>","generation":N,
//	 "issued_at":"<rfc3339>","approvals":[{"addon":"…","digest":"sha256:<64hex>"}]}
//
// The gateway only carries it (desired-config `workload_approvals`). This node
// verifies it over the exact bytes, binds it to its own id, refuses a lower
// generation (rollback) and keeps the newest it accepted in its own state
// file, which it re-verifies on every read. A set admits anything only on a
// node whose root owner opted in (optin.go; written by
// `noo node workloads controller allow` and never by this agent), and never
// under policy none.

// ControllerSetKind is the document's kind: domain separation from every
// other document the fleet key signs (a model-set manifest above all).
const ControllerSetKind = "noomesh.node-workload-approvals/v1"

// ControllerApprovalsFile holds the newest verified set, in the agent's state
// directory. The agent writes it; it is not the owner's local store.
const ControllerApprovalsFile = "controller-workload-approvals.json"

// maxControllerFile bounds what is read back: a set this size is not one the
// controller signed.
const maxControllerFile = 1 << 20

// The distinct refusals. Each names one check, so a test can pin each.
var (
	ErrSetSignature   = errors.New("the approval set's signature does not verify against signing.pub")
	ErrSetDecode      = errors.New("the approval set is not one strict JSON document of the expected shape")
	ErrSetKind        = errors.New("the approval set's kind is not " + ControllerSetKind)
	ErrSetNode        = errors.New("the approval set is bound to another node")
	ErrSetGeneration  = errors.New("the approval set's generation is below 1")
	ErrSetIssuedAt    = errors.New("the approval set's issued_at is not an RFC 3339 time")
	ErrSetApprovals   = errors.New("the approval set has no approvals list")
	ErrSetEntry       = errors.New("an approval set entry is not an add-on and one exact digest")
	ErrSetDuplicate   = errors.New("the approval set names the same add-on and digest twice")
	ErrSetRollback    = errors.New("the approval set's generation is below the one this node holds")
	ErrSetConflict    = errors.New("the approval set reuses the held generation with different bytes")
	ErrSetNoKey       = errors.New("there is no fleet signing key to verify the approval set with")
	ErrSetPersisted   = errors.New("the persisted controller approval set cannot be read")
	ErrSetDeliveryBad = errors.New("desired-config's workload_approvals is not {doc, sig} in base64")
)

// ControllerSet is a verified approval set.
type ControllerSet struct {
	Kind       string     `json:"kind"`
	Node       string     `json:"node"`
	Generation int64      `json:"generation"`
	IssuedAt   string     `json:"issued_at"`
	Approvals  []Approval `json:"approvals"`
}

// VerifyControllerSet checks doc against sig and this node, in this order:
// the signature over the exact bytes (nothing is parsed before it holds);
// one strict JSON value (no unknown field, nothing after it); the kind; the
// node, exactly; generation >= 1; issued_at; every entry; no duplicate.
func VerifyControllerSet(pub *ecdsa.PublicKey, selfNode string, doc, sig []byte) (*ControllerSet, error) {
	if pub == nil {
		return nil, ErrSetNoKey
	}
	if !modelsets.VerifySignature(pub, doc, sig) {
		return nil, ErrSetSignature
	}
	var s ControllerSet
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSetDecode, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the document", ErrSetDecode)
	}
	if s.Kind != ControllerSetKind {
		return nil, fmt.Errorf("%w (it is %q)", ErrSetKind, s.Kind)
	}
	if selfNode == "" || s.Node != selfNode {
		return nil, fmt.Errorf("%w (%q, this node is %q)", ErrSetNode, s.Node, selfNode)
	}
	if s.Generation < 1 {
		return nil, fmt.Errorf("%w (%d)", ErrSetGeneration, s.Generation)
	}
	if _, err := time.Parse(time.RFC3339, s.IssuedAt); err != nil {
		return nil, fmt.Errorf("%w (%q)", ErrSetIssuedAt, s.IssuedAt)
	}
	if s.Approvals == nil {
		return nil, ErrSetApprovals
	}
	seen := map[Approval]bool{}
	for _, x := range s.Approvals {
		if err := checkApproval(x); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSetEntry, err)
		}
		if seen[x] {
			return nil, fmt.Errorf("%w (%s at %s)", ErrSetDuplicate, x.Addon, x.Digest)
		}
		seen[x] = true
	}
	return &s, nil
}

// signedDoc is the persisted file and the desired-config field alike: the
// document and its signature, each base64 (standard, padded).
type signedDoc struct {
	Doc string `json:"doc"`
	Sig string `json:"sig"`
}

func decodeSigned(b []byte) (doc, sig []byte, err error) {
	var w signedDoc
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("data after the JSON value")
	}
	doc, err = base64.StdEncoding.DecodeString(w.Doc)
	if err != nil || len(doc) == 0 {
		return nil, nil, errors.New("doc is not base64")
	}
	sig, err = base64.StdEncoding.DecodeString(w.Sig)
	if err != nil || len(sig) == 0 {
		return nil, nil, errors.New("sig is not base64")
	}
	return doc, sig, nil
}

// DecodeDelivery reads desired-config's `workload_approvals` value. Its
// contents are not trusted: Offer verifies them.
func DecodeDelivery(raw json.RawMessage) (doc, sig []byte, err error) {
	doc, sig, err = decodeSigned(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSetDeliveryBad, err)
	}
	return doc, sig, nil
}

// ControllerApprovals is this node's newest verified controller set and the
// owner's opt-in that decides whether it counts.
type ControllerApprovals struct {
	dir     string
	node    string
	pubPath string
	// optInUID is the owner the opt-in file must have: root. A field only so
	// a test that is not root can stand in for it.
	optInUID uint32
	mu       sync.Mutex
}

// NewControllerApprovals keeps the set in dir (the agent's StateDir), bound
// to node (the agent's node id, the one desired-config is fetched for), and
// verifies it with the fleet signing key at signingPub.
func NewControllerApprovals(dir, node, signingPub string) *ControllerApprovals {
	return &ControllerApprovals{dir: dir, node: node, pubPath: signingPub}
}

func (c *ControllerApprovals) path() string { return filepath.Join(c.dir, ControllerApprovalsFile) }

func (c *ControllerApprovals) key() (*ecdsa.PublicKey, error) {
	pub, err := modelsets.LoadSigningKey(c.pubPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSetNoKey, err)
	}
	return pub, nil
}

// load returns the persisted set and its document bytes, re-verified; (nil,
// nil, nil) when there is none. A file that is there and does not verify is an
// ERROR, never "no set".
func (c *ControllerApprovals) load() (*ControllerSet, []byte, error) {
	p := c.path()
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSetPersisted, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %s is not a regular file", ErrSetPersisted, p)
	}
	if fi.Size() > maxControllerFile {
		return nil, nil, fmt.Errorf("%w: %s is %d bytes", ErrSetPersisted, p, fi.Size())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSetPersisted, err)
	}
	doc, sig, err := decodeSigned(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrSetPersisted, p, err)
	}
	pub, err := c.key()
	if err != nil {
		return nil, nil, err
	}
	s, err := VerifyControllerSet(pub, c.node, doc, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s no longer verifies: %w", ErrSetPersisted, p, err)
	}
	return s, doc, nil
}

// heldGeneration is the held document's generation, read WITHOUT verifying
// it: only ever a floor for Offer, never a reason to admit anything.
func (c *ControllerApprovals) heldGeneration() (int64, error) {
	p := c.path()
	fi, err := os.Lstat(p)
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxControllerFile {
		return 0, fmt.Errorf("%s is not a held set", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}
	doc, _, err := decodeSigned(b)
	if err != nil {
		return 0, err
	}
	var s ControllerSet
	if err := json.Unmarshal(doc, &s); err != nil {
		return 0, err
	}
	return s.Generation, nil
}

// Offer takes a set the gateway delivered. It is verified first; then it
// must not be older than the held one (rollback), an equal generation must
// be the same bytes (a no-op), and a newer one replaces the held one
// atomically. A held set that no longer verifies (a rotated fleet key) is
// replaced only by a newer generation. Any error leaves the held set exactly as it was. gen is the
// generation now held.
func (c *ControllerApprovals) Offer(doc, sig []byte) (gen int64, changed bool, err error) {
	pub, err := c.key()
	if err != nil {
		return 0, false, err
	}
	s, err := VerifyControllerSet(pub, c.node, doc, sig)
	if err != nil {
		return 0, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cur, curDoc, err := c.load()
	if err != nil {
		// The held set no longer verifies: the fleet key was rotated
		// (`noo security pki rotate-signing-key`), or the file was damaged.
		// Its generation, read without trust, is still the floor, so only a
		// NEWER set signed with the current key replaces it: the operator
		// re-signs generation N+1, and an older set is never replayed. A
		// file whose generation cannot be read at all sets no floor; writing
		// one takes the agent's own access to its state directory.
		if floor, ferr := c.heldGeneration(); ferr == nil && s.Generation <= floor {
			return 0, false, fmt.Errorf("%w (offered %d, the unverifiable held set is %d): %w", ErrSetRollback, s.Generation, floor, err)
		}
		slog.Warn("controller approvals: replacing a held set that no longer verifies with a newer verified one", "error", err, "generation", s.Generation)
		cur = nil
	}
	if cur != nil {
		switch {
		case s.Generation < cur.Generation:
			return cur.Generation, false, fmt.Errorf("%w (offered %d, held %d)", ErrSetRollback, s.Generation, cur.Generation)
		case s.Generation == cur.Generation && !bytes.Equal(doc, curDoc):
			return cur.Generation, false, fmt.Errorf("%w (generation %d)", ErrSetConflict, s.Generation)
		case s.Generation == cur.Generation:
			return cur.Generation, false, nil
		}
	}
	b, err := json.Marshal(signedDoc{Doc: base64.StdEncoding.EncodeToString(doc), Sig: base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return 0, false, err
	}
	if err := writeFileAtomic(c.dir, ControllerApprovalsFile, b); err != nil {
		return 0, false, err
	}
	return s.Generation, true, nil
}

// writeFileAtomic replaces dir/name: a temp file in dir, 0600, fsynced, then
// renamed over it.
func writeFileAtomic(dir, name string, b []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	tname := tmp.Name()
	defer os.Remove(tname) // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tname, filepath.Join(dir, name))
}

// Has reports whether the controller set admits exactly (addon, digest), and
// the generation that does. A node whose owner has not opted in ignores the
// set entirely: false, and no error. Opted in, a set that cannot be read or
// verified is an error (the caller refuses).
func (c *ControllerApprovals) Has(addon, digest string) (bool, int64, error) {
	if !c.optedIn() {
		return false, 0, nil
	}
	c.mu.Lock()
	s, _, err := c.load()
	c.mu.Unlock()
	if err != nil {
		return false, 0, err
	}
	if s == nil {
		return false, 0, nil
	}
	for _, x := range s.Approvals {
		if x.Addon == addon && x.Digest == digest {
			return true, s.Generation, nil
		}
	}
	return false, s.Generation, nil
}

// List is the held set's approvals when the owner opted in; nil when not
// opted in or no set is held. The error means the set cannot be verified.
func (c *ControllerApprovals) List() ([]Approval, int64, error) {
	if !c.optedIn() {
		return nil, 0, nil
	}
	c.mu.Lock()
	s, _, err := c.load()
	c.mu.Unlock()
	if err != nil || s == nil {
		return nil, 0, err
	}
	out := append([]Approval(nil), s.Approvals...)
	sortApprovals(out)
	return out, s.Generation, nil
}

// optedIn is OptedIn for this node's state directory; a bad opt-in file is
// "not opted in", and is logged.
func (c *ControllerApprovals) optedIn() bool {
	ok, err := optedIn(c.dir, c.optInUID)
	if err != nil {
		slog.Warn("controller approvals: the opt-in file is not one root wrote; ignoring the controller set", "error", err)
	}
	return ok
}

// Status is the heartbeat's `addon_workloads_controller`: whether the owner
// opted in, and what set this node holds (`set_state` none, verified or
// unverifiable; generation and set_sha256, the SHA-256 of the signed
// document's bytes, with a verified one).
func (c *ControllerApprovals) Status() map[string]any {
	out := map[string]any{"opted_in": c.optedIn()}
	c.mu.Lock()
	s, doc, err := c.load()
	c.mu.Unlock()
	switch {
	case err != nil:
		slog.Warn("heartbeat: the held controller approval set does not verify", "error", err)
		out["set_state"] = "unverifiable"
	case s == nil:
		out["set_state"] = "none"
	default:
		sum := sha256.Sum256(doc)
		out["set_state"] = "verified"
		out["generation"] = s.Generation
		out["set_sha256"] = hex.EncodeToString(sum[:])
	}
	return out
}
