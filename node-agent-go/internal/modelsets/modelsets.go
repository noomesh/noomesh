// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package modelsets is the node's half of the i300 model-set rail: it fetches
// the sets a desired-config names, verifies them, holds them read-only and
// reports their state. Contract: docs/reference/node-workloads.md ("Signing a
// model set", "Rail delivery").
//
// A set lives at <Root>/<id>/<revision>/ (Root is <models dir>/sets):
//
//	model-set.json   the signed manifest, exact bytes
//	.verified        written LAST; sha256 of model-set.json
//	<files...>       each checked against the manifest's sha256 and bytes
//
// Trust is a chain with no gaps: the signature (fleet signing key, ECDSA P-384
// over SHA-256, checked over the EXACT manifest bytes before they are parsed)
// covers the manifest; the manifest covers every file by sha256 and size. A
// directory without `.verified` is never "verified", whatever it holds.
package modelsets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlenv"
	"github.com/noomesh/noomesh/node-agent-go/internal/mutant"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

const (
	// ManifestName and MarkerName are the two files the node itself writes.
	ManifestName = "model-set.json"
	MarkerName   = ".verified"
	// railSigName is the detached signature the CONTROLLER keeps beside a
	// staged set. A directory holding it is the rail's staging area (this
	// node is the controller's host), not a node copy: the node never writes
	// into it, seals it or prunes it.
	railSigName = "model-set.json.sig"

	// DiskMarginMin and DiskMarginPercent are the free space a fetch must
	// leave on the data root beyond the bytes it writes: the larger of the
	// two. PROVISIONAL: a guess that keeps a node from filling its disk with
	// a set, to be tuned once real sets and real disks have been measured.
	DiskMarginMin     = uint64(2) << 30
	DiskMarginPercent = 10

	// refusedRetry is how long a refused set waits before the next attempt,
	// so a tampered set is not re-downloaded every tick.
	refusedRetry = 30 * time.Minute

	fileFetchTimeout = 90 * time.Minute
	maxManifestBody  = 4 << 20
)

// State of a set on this node.
type State string

const (
	StateVerified State = "verified"
	StateFetching State = "fetching"
	StateRefused  State = "refused"
	StateAbsent   State = "absent"
)

// Ref names one revision of one set.
type Ref struct{ ID, Revision string }

func (r Ref) String() string { return r.ID + "@" + r.Revision }

// Status is State plus, for refused, the reason code (nodewl.Reason*).
type Status struct {
	State  State
	Reason string
}

// Row is one `model_sets` heartbeat entry.
type Row struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
}

// Refusal is a fetch that must not be retried blindly: the set did not check
// out. Reason is a code of the contract's vocabulary.
type Refusal struct{ Reason, Detail string }

func (r *Refusal) Error() string { return r.Reason + ": " + r.Detail }

func refuse(reason, format string, a ...any) *Refusal {
	return &Refusal{Reason: reason, Detail: fmt.Sprintf(format, a...)}
}

// ErrNotStaged is the rail's 404: no such set, or no signature.
var ErrNotStaged = errors.New("the controller has not staged that set")

// Signed is the gateway's modelset manifest answer.
type Signed struct {
	ID          string `json:"id"`
	Revision    string `json:"revision"`
	ManifestB64 string `json:"manifest_b64"`
	SigB64      string `json:"sig_b64"`
}

// Fetcher is the verified-download half of internal/preseed.
type Fetcher interface {
	FetchOneVerified(ctx context.Context, fileURL, dest, sha256hex string) (bool, error)
}

// railFiles builds a preseed client per call, so a rotated node leaf is
// picked up without a restart (the same rule as the model_file job).
type railFiles struct{}

func (railFiles) FetchOneVerified(ctx context.Context, fileURL, dest, sha string) (bool, error) {
	return preseed.New().FetchOneVerified(ctx, fileURL, dest, sha)
}

type memState struct {
	state  State
	reason string
	until  time.Time // refused: do not retry before this
}

// Store holds the model sets of this node. Every field is a seam a test sets;
// New fills them with the production ones.
type Store struct {
	// Root is <models dir>/sets. Nothing outside it is ever written or removed.
	Root string
	// SigningPub is the path of the fleet signing public key (signing.pub).
	SigningPub string
	// Manifest asks the gateway for a set's signed manifest.
	Manifest func(ctx context.Context, ref Ref) (*Signed, error)
	// Files downloads one file, verified against its sha256.
	Files Fetcher
	// CacheURL is the model cache's base URL ("" = no data plane).
	CacheURL func() string
	// Free is the free bytes on the filesystem holding path.
	Free func(path string) (uint64, error)
	// Now is the clock.
	Now func() time.Time

	mu      sync.Mutex
	mem     map[Ref]memState
	want    map[Ref]bool
	armed   bool
	running bool
	wg      sync.WaitGroup
}

// New is the production Store for the models dir root (docker.ModelsDir()).
func New(modelsDir string, cfg *config.Config) *Store {
	return &Store{
		Root:       filepath.Join(modelsDir, "sets"),
		SigningPub: signingPubPath(cfg),
		Manifest:   gatewayManifest(cfg),
		Files:      railFiles{},
		CacheURL:   preseed.CacheURL,
		Free:       freeBytes,
		Now:        time.Now,
	}
}

// signingPubPath is signing.pub in the node's PKI directory: the directory
// of the cluster CA the agent is configured with (/etc/noo/pki on Linux,
// ~/noomesh/pki on macOS), else NOO_PKI_DIR. "" when neither is known.
func signingPubPath(cfg *config.Config) string {
	if cfg != nil && cfg.TLSCA != "" {
		return filepath.Join(filepath.Dir(cfg.TLSCA), "signing.pub")
	}
	if d := ctrlenv.PKIDir(); d != "" {
		return filepath.Join(d, "signing.pub")
	}
	return ""
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) dir(ref Ref) string { return filepath.Join(s.Root, ref.ID, ref.Revision) }

// Dir is the directory a set lives in on this node: what a worker mounts
// read-only. It says nothing about the set's state; ask State first.
func (s *Store) Dir(ref Ref) string { return s.dir(ref) }

// ---- signature ----------------------------------------------------------

// LoadSigningKey reads an SPKI PEM public key and requires ECDSA on P-384,
// the fleet signing key's algorithm.
func LoadSigningKey(path string) (*ecdsa.PublicKey, error) {
	if path == "" {
		return nil, errors.New("no PKI directory is configured, so there is no signing.pub")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing.pub unreadable: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not an SPKI public key: %w", path, err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, fmt.Errorf("%s is not an ECDSA P-384 key", path)
	}
	return pub, nil
}

// VerifySignature is `openssl dgst -sha256 -verify`: ECDSA over the SHA-256
// digest of the EXACT manifest bytes, DER-encoded. The manifest is never
// parsed, let alone re-serialised, before this returns true.
func VerifySignature(pub *ecdsa.PublicKey, manifest, sig []byte) bool {
	digest := sha256.Sum256(manifest)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

// ---- gateway ------------------------------------------------------------

func gatewayManifest(cfg *config.Config) func(context.Context, Ref) (*Signed, error) {
	return func(ctx context.Context, ref Ref) (*Signed, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		u := fmt.Sprintf("%s/api/artifacts/manifest/modelset/%s", strings.TrimRight(cfg.ControllerURL, "/"), url.PathEscape(ref.String()))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if cfg.ClusterSecret != "" {
			if err := auth.SetClusterAuth(req, cfg.NodeID, cfg.ClusterSecret); err != nil {
				return nil, fmt.Errorf("sign manifest request: %w", err)
			}
		}
		tr, err := cfg.HTTPTransport()
		if err != nil {
			return nil, fmt.Errorf("TLS transport: %w", err)
		}
		defer tr.CloseIdleConnections()
		return doManifest(&http.Client{Timeout: time.Minute, Transport: tr}, req)
	}
}

// doManifest runs the request and classifies the answer.
func doManifest(c *http.Client, req *http.Request) (*Signed, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("manifest request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusBadRequest:
		return nil, ErrNotStaged
	default:
		return nil, fmt.Errorf("manifest request answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBody))
	if err != nil {
		return nil, fmt.Errorf("read manifest answer: %w", err)
	}
	var out Signed
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("manifest answer is not JSON: %w", err)
	}
	return &out, nil
}

// ---- fetch --------------------------------------------------------------

// Fetch brings one set to this node and seals it. It returns nil when the set
// is verified on disk (already, or now), a *Refusal when the set did not check
// out (the state is then `refused`), and another error for a failure that says
// nothing about the set (network, a full read of free space): retry later.
func (s *Store) Fetch(ctx context.Context, ref Ref) (err error) {
	if !nodewl.ValidSetRef(ref.ID, ref.Revision) {
		return s.refused(ref, refuse(nodewl.ReasonSetSlotInvalid, "set id or revision is malformed"))
	}
	s.mu.Lock()
	if s.mem[ref].state == StateFetching {
		s.mu.Unlock()
		return fmt.Errorf("%s is already being fetched", ref)
	}
	if s.diskStatusLocked(ref).State == StateVerified {
		delete(s.mem, ref)
		s.mu.Unlock()
		return nil
	}
	s.setMem(ref, memState{state: StateFetching})
	s.mu.Unlock()

	defer func() {
		var r *Refusal
		switch {
		case err == nil:
			s.clearMem(ref)
		case errors.As(err, &r):
			err = s.refused(ref, r)
		default:
			s.clearMem(ref) // says nothing about the set: not refused, retried
		}
	}()
	return s.fetch(ctx, ref)
}

func (s *Store) refused(ref Ref, r *Refusal) error {
	slog.Warn("model set refused", "set", ref.String(), "reason", r.Reason, "detail", r.Detail)
	s.mu.Lock()
	s.setMem(ref, memState{state: StateRefused, reason: r.Reason, until: s.now().Add(refusedRetry)})
	s.mu.Unlock()
	return r
}

func (s *Store) setMem(ref Ref, m memState) {
	if s.mem == nil {
		s.mem = map[Ref]memState{}
	}
	s.mem[ref] = m
}

func (s *Store) clearMem(ref Ref) {
	s.mu.Lock()
	delete(s.mem, ref)
	s.mu.Unlock()
}

func (s *Store) fetch(ctx context.Context, ref Ref) error {
	dir := s.dir(ref)
	if err := noSymlinkPath(s.Root, dir); err != nil {
		return refuse(nodewl.ReasonSetUnverified, "%v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, railSigName)); err == nil {
		return refuse(nodewl.ReasonControllerHost, "%s is the controller's own staged copy of the set", dir)
	}

	// 1. The signed manifest, from the gateway.
	signed, err := s.Manifest(ctx, ref)
	if errors.Is(err, ErrNotStaged) {
		return refuse(nodewl.ReasonSetMissing, "the controller has not staged %s", ref)
	}
	if err != nil {
		return err
	}
	manifest, err := base64.StdEncoding.DecodeString(signed.ManifestB64)
	if err != nil || len(manifest) == 0 {
		return refuse(nodewl.ReasonSetUnverified, "manifest_b64 is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(signed.SigB64)
	if err != nil || len(sig) == 0 {
		return refuse(nodewl.ReasonSetUnverified, "sig_b64 is not base64")
	}

	// 2. The signature, over the exact bytes, BEFORE anything reads them.
	pub, err := LoadSigningKey(s.SigningPub)
	if err != nil {
		return refuse(nodewl.ReasonSetUnverified, "cannot verify: %v", err)
	}
	if !VerifySignature(pub, manifest, sig) {
		return refuse(nodewl.ReasonSetUnverified, "the manifest signature does not verify")
	}

	// 3. The contract's own validator, and the identity of what was asked for.
	set, err := nodewl.ParseModelSet(manifest)
	if err != nil {
		return refuse(nodewl.ReasonSetUnverified, "manifest invalid (%s): %v", nodewl.CodeOf(err), err)
	}
	if set.ID != ref.ID || set.Revision != ref.Revision {
		return refuse(nodewl.ReasonSetUnverified, "asked for %s, the signed manifest is %s@%s", ref, set.ID, set.Revision)
	}
	dests := make([]string, len(set.Files))
	for i, f := range set.Files {
		dest, err := setFileDest(dir, f.Path)
		if err != nil {
			return err
		}
		dests[i] = dest
	}

	// 4. Disk.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := makeWritable(dir); err != nil {
		return fmt.Errorf("reopen %s: %w", dir, err)
	}
	if err := noSymlinks(dir); err != nil {
		return refuse(nodewl.ReasonSetUnverified, "%v", err)
	}
	if err := s.checkDisk(set, dir); err != nil {
		return err
	}

	// 5. The files.
	cache := strings.TrimRight(s.CacheURL(), "/")
	if cache == "" {
		return errors.New("NOO_MODEL_CACHE_URL is not set: no data plane to fetch model sets from")
	}
	for i, f := range set.Files {
		dest := dests[i]
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(dest), err)
		}
		src := cache + "/sets/" + url.PathEscape(ref.ID) + "/" + url.PathEscape(ref.Revision) + "/" + escapePath(f.Path)
		fctx, cancel := context.WithTimeout(ctx, fileFetchTimeout)
		_, err := s.Files.FetchOneVerified(fctx, src, dest, f.SHA256)
		cancel()
		if errors.Is(err, preseed.ErrDigestMismatch) {
			return refuse(nodewl.ReasonSetUnverified, "%s: %v", f.Path, err)
		}
		if err != nil {
			return fmt.Errorf("fetch %s of %s: %w", f.Path, ref, err)
		}
	}

	// 6. Check what is on disk, then seal: manifest, files read-only, marker
	// LAST, directories read-only.
	if err := noSymlinks(dir); err != nil {
		return refuse(nodewl.ReasonSetUnverified, "%v", err)
	}
	if err := removeStrays(dir, set); err != nil {
		return err
	}
	for _, f := range set.Files {
		fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != f.Bytes {
			return refuse(nodewl.ReasonSetUnverified, "%s is not %d regular bytes on disk", f.Path, f.Bytes)
		}
	}
	if err := writeAtomic(filepath.Join(dir, ManifestName), manifest); err != nil {
		return err
	}
	if err := sealFiles(dir); err != nil {
		return err
	}
	sum := sha256.Sum256(manifest)
	if err := writeAtomic(filepath.Join(dir, MarkerName), []byte(hex.EncodeToString(sum[:])+"\n")); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(dir, MarkerName), 0o444); err != nil {
		return err
	}
	if err := sealDirs(dir); err != nil {
		return err
	}
	if uid, ok := ownerUID(dir); ok && uid != 0 {
		slog.Warn("model set sealed read-only, but not root-owned: the agent cannot chown (a privileged noo-hostd op would be needed)",
			"set", ref.String(), "owner_uid", uid)
	}
	slog.Info("model set verified", "set", ref.String(), "files", len(set.Files))
	return nil
}

func (s *Store) checkDisk(set *nodewl.ModelSet, dir string) error {
	var need int64
	for _, f := range set.Files {
		if fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(f.Path))); err == nil && fi.Mode().IsRegular() && fi.Size() == f.Bytes {
			continue // already here: costs nothing more
		}
		need += f.Bytes
	}
	required := uint64(need) + margin(need)
	free, err := s.Free(nearest(dir))
	if err != nil {
		return fmt.Errorf("free space of %s: %w", dir, err)
	}
	if free < required {
		return refuse(nodewl.ReasonDisk, "%d bytes free, %d needed (files %d + margin)", free, required, need)
	}
	return nil
}

// margin is DiskMarginPercent of the bytes to write, at least DiskMarginMin.
func margin(need int64) uint64 {
	m := uint64(need) / 100 * DiskMarginPercent
	return max(m, DiskMarginMin)
}

// nearest is the closest existing ancestor of p (statfs needs a real path).
func nearest(p string) string {
	for {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// setFileDest is where one manifest file lands under dir. The path becomes a
// filesystem path here, so the node's own mount rule (nodewl.ValidSetPath:
// relative, no `.`/`..` component, one directory level, a fixed charset) is
// asserted at the point of use, whatever parsed the manifest before.
// ValidSetPath is the rule; within is defence in depth against a future
// loosening of it, and is unreachable today (it is pinned directly by
// TestWithinRefusesEverythingOutsideTheDir).
func setFileDest(dir, p string) (string, error) {
	if !nodewl.ValidSetPath(p) {
		return "", refuse(nodewl.ReasonSetUnverified, "file path %q is not allowed", p)
	}
	dest := filepath.Join(dir, filepath.FromSlash(p))
	if !within(dir, dest) {
		return "", refuse(nodewl.ReasonSetUnverified, "file path %q leaves the set directory", p)
	}
	return dest, nil
}

func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ---- filesystem hygiene -------------------------------------------------

// noSymlinkPath refuses a symlink at any component from root down to p.
func noSymlinkPath(root, p string) error {
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("%s is outside %s", p, root)
	}
	cur := root
	for _, c := range append([]string{""}, strings.Split(rel, string(filepath.Separator))...) {
		cur = filepath.Join(cur, c)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", cur)
		}
	}
	return nil
}

// noSymlinks refuses a symlink anywhere under dir.
func noSymlinks(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", p)
		}
		return nil
	})
}

// makeWritable reopens a sealed tree so a re-fetch can write into it. It
// never follows a symlink.
func makeWritable(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			return nil
		case d.IsDir():
			return os.Chmod(p, 0o755)
		default:
			return os.Chmod(p, 0o644)
		}
	})
}

// removeStrays deletes a regular file the manifest does not list (a leftover
// .partial, a file from an earlier revision of the tooling): the sealed set
// is exactly the manifest's files.
func removeStrays(dir string, set *nodewl.ModelSet) error {
	keep := map[string]bool{MarkerName: true, ManifestName: true}
	for _, f := range set.Files {
		keep[f.Path] = true
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if keep[filepath.ToSlash(rel)] {
			return nil
		}
		return os.Remove(p)
	})
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// sealFiles makes every regular file 0444.
func sealFiles(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			return os.Chmod(p, 0o444)
		}
		return nil
	})
}

// sealDirs makes every directory 0555, children before parents.
func sealDirs(dir string) error {
	var dirs []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i], 0o555); err != nil {
			return err
		}
	}
	return nil
}

// ---- state --------------------------------------------------------------

// State is the state of one set. A directory without `.verified` is never
// verified.
func (s *Store) State(ref Ref) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked(ref)
}

// VerifiedManifest is the parsed manifest of a set that is verified on this
// node (the gate reads a profile's min_compute from it). Any other state is an
// error: only a manifest whose signature, files and marker were checked is read.
func (s *Store) VerifiedManifest(ref Ref) (nodewl.ModelSet, error) {
	if st := s.State(ref); st.State != StateVerified && !mutant.On("ms_state") {
		return nodewl.ModelSet{}, fmt.Errorf("set %s is %s here", ref, st.State)
	}
	b, err := os.ReadFile(filepath.Join(s.dir(ref), ManifestName))
	if err != nil {
		if mutant.On("ms_read") {
			return nodewl.ModelSet{}, nil
		}
		return nodewl.ModelSet{}, err
	}
	set, err := nodewl.ParseModelSet(b)
	if err != nil {
		if mutant.On("ms_parse") {
			return nodewl.ModelSet{}, nil
		}
		return nodewl.ModelSet{}, err
	}
	return *set, nil
}

func (s *Store) statusLocked(ref Ref) Status {
	m, inMem := s.mem[ref]
	if inMem && m.state == StateFetching {
		return Status{State: StateFetching}
	}
	if d := s.diskStatusLocked(ref); d.State != StateAbsent {
		return d
	}
	if inMem && m.state == StateRefused {
		return Status{State: StateRefused, Reason: m.reason}
	}
	return Status{State: StateAbsent}
}

// diskStatusLocked judges the directory alone: marker present and every
// recorded fact still true (manifest bytes match the marker, still parse as
// this ref, every file a regular file of the manifest's size, no symlink).
// Hashes are not re-read: they were checked at fetch, and the files are
// read-only.
func (s *Store) diskStatusLocked(ref Ref) Status {
	dir := s.dir(ref)
	marker, err := os.ReadFile(filepath.Join(dir, MarkerName))
	if err != nil {
		return Status{State: StateAbsent}
	}
	bad := Status{State: StateRefused, Reason: nodewl.ReasonSetUnverified}
	if noSymlinkPath(s.Root, dir) != nil || noSymlinks(dir) != nil {
		return bad
	}
	manifest, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return bad
	}
	sum := sha256.Sum256(manifest)
	if strings.TrimSpace(string(marker)) != hex.EncodeToString(sum[:]) {
		return bad
	}
	set, err := nodewl.ParseModelSet(manifest)
	if err != nil || set.ID != ref.ID || set.Revision != ref.Revision {
		return bad
	}
	for _, f := range set.Files {
		fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != f.Bytes {
			return bad
		}
	}
	return Status{State: StateVerified}
}

// Rows is the heartbeat's `model_sets`: a row for every set referenced by the
// last desired-config or present on disk. ok is false when the state cannot be
// read (nothing was ever read from desired-config, or the sets directory is
// unreadable): the caller then omits the key. An empty slice with ok is a real
// "none".
func (s *Store) Rows() (rows []Row, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.armed {
		return nil, false
	}
	refs := map[Ref]bool{}
	for r := range s.want {
		refs[r] = true
	}
	ents, err := os.ReadDir(s.Root)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	for _, id := range ents {
		if !id.IsDir() {
			continue
		}
		revs, err := os.ReadDir(filepath.Join(s.Root, id.Name()))
		if err != nil {
			return nil, false
		}
		for _, rev := range revs {
			if rev.IsDir() && nodewl.ValidSetRef(id.Name(), rev.Name()) {
				refs[Ref{id.Name(), rev.Name()}] = true
			}
		}
	}
	rows = []Row{}
	for r := range refs {
		st := s.statusLocked(r)
		if st.State == StateAbsent {
			if !s.want[r] {
				continue // a leftover partial nobody asked for
			}
			st.State = StateFetching // wanted, queued or between retries
		}
		rows = append(rows, Row{ID: r.ID, Revision: r.Revision, State: string(st.State), Reason: st.Reason})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ID != rows[j].ID {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].Revision < rows[j].Revision
	})
	return rows, true
}

// ---- sync and prune -----------------------------------------------------

// Sync records the sets desired-config names and starts, off the caller's
// goroutine, one worker that fetches the missing ones one at a time. A second
// Sync while the worker runs only updates the wanted list: no duplicate fetch
// is ever in flight.
func (s *Store) Sync(ctx context.Context, want []Ref) {
	s.mu.Lock()
	s.armed = true
	s.want = make(map[Ref]bool, len(want))
	for _, r := range want {
		s.want[r] = true
	}
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.wg.Add(1)
	s.mu.Unlock()
	go s.work(ctx)
}

// Wait blocks until the worker is idle (tests).
func (s *Store) Wait() { s.wg.Wait() }

func (s *Store) work(ctx context.Context) {
	defer s.wg.Done()
	tried := map[Ref]bool{}
	for ctx.Err() == nil {
		ref, ok := s.next(tried)
		if !ok {
			return
		}
		tried[ref] = true
		if err := s.Fetch(ctx, ref); err != nil {
			var r *Refusal
			if !errors.As(err, &r) {
				slog.Warn("model set fetch failed; will retry", "set", ref.String(), "error", err)
			}
		}
	}
}

// next picks the first wanted set that is neither waiting out a refusal nor
// already tried this run; it clears `running` when there is none. A set that is
// already verified is not skipped here: Fetch returns for it at once, before
// it asks anybody anything, and drops any stale in-memory state on the way.
func (s *Store) next(tried map[Ref]bool) (Ref, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := make([]Ref, 0, len(s.want))
	for r := range s.want {
		refs = append(refs, r)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	for _, r := range refs {
		if tried[r] {
			continue
		}
		if m, ok := s.mem[r]; ok && m.state == StateRefused && s.now().Before(m.until) {
			continue
		}
		return r, true
	}
	s.running = false
	return Ref{}, false
}

// Prune removes every set revision on disk that keep does not name, and
// returns what it removed. It touches only <Root>/<id>/<revision> directories
// whose names fit the schema; it skips a revision being fetched, a symlink,
// and the controller's own staged copy (a directory holding the rail's
// signature). The caller passes keep only when desired-config was read: an
// error is never "nothing referenced".
func (s *Store) Prune(keep map[Ref]bool) ([]Ref, error) {
	if fi, err := os.Lstat(s.Root); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", s.Root)
	}
	ids, err := os.ReadDir(s.Root)
	if err != nil {
		return nil, err
	}
	var removed []Ref
	for _, id := range ids {
		idDir := filepath.Join(s.Root, id.Name())
		if fi, err := os.Lstat(idDir); err != nil || !fi.IsDir() {
			continue // a symlink or a stray file is not ours to touch
		}
		revs, err := os.ReadDir(idDir)
		if err != nil {
			return removed, err
		}
		for _, rev := range revs {
			ref := Ref{id.Name(), rev.Name()}
			if !nodewl.ValidSetRef(ref.ID, ref.Revision) || keep[ref] {
				continue
			}
			dir := s.dir(ref)
			// A symlink or a file is not ours to remove. within is defence in
			// depth against a future loosening of ValidSetRef, which keeps it
			// unreachable today.
			if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || !within(s.Root, dir) {
				continue
			}
			if _, err := os.Lstat(filepath.Join(dir, railSigName)); err == nil {
				continue
			}
			s.mu.Lock()
			busy := s.mem[ref].state == StateFetching
			s.mu.Unlock()
			if busy {
				continue
			}
			if err := makeWritable(dir); err != nil {
				return removed, err
			}
			if err := os.RemoveAll(dir); err != nil {
				return removed, err
			}
			s.clearMem(ref)
			removed = append(removed, ref)
			slog.Info("model set pruned", "set", ref.String())
		}
		_ = os.Remove(idDir) // only succeeds when empty
	}
	return removed, nil
}
