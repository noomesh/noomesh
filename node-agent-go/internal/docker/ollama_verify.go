// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Verifying the bytes a placed Ollama model loads, against the CONTROLLER.
//
// Ollama loads a model from its store: the manifest at
// <models>/manifests/registry.ollama.ai/<ns>/<name>/<tag> names a config and
// layers by digest, and each is a file <models>/blobs/sha256-<hex>. Nothing in
// ollama checks those bytes at load. Anyone who can write the store can
// replace a blob, or rewrite the manifest to point at a new blob that is
// perfectly self-consistent (it hashes to its own name). So hashing blobs
// against their own names proves nothing; the trust anchor is the
// controller's artifact store, and the check is "the store holds what the
// controller says this model is":
//
//   - mirror: the controller holds the registry manifest (ollamamanifest
//     kind): staged with every blob (`noo models fetch ollama:<tag>`), or
//     recorded alone when it pulled the tag (`noo models pull`, onboard). The
//     local manifest's config digest and layer digest SET must equal the
//     controller's, and every one of those blobs must hash to its digest. It
//     proves the bytes are what the controller recorded, not that the
//     registry served the right model. A record with no bytes in the store
//     cannot repair: a mismatch is refused, and the remedy is a re-pull.
//   - gguf: the controller publishes <name>.Modelfile (a converted model,
//     e.g. harrier, or a tag staged as GGUF + Modelfile). The local manifest's
//     MODEL layer must be sha256:<the controller's gguf sha256 for the file
//     the Modelfile's FROM names>, and that blob must hash to it.
//   - none: no controller record (a hand `ollama pull`). Reported as
//     unverified, never refused: `noo models pull <model>` re-pulls it through
//     the controller, which writes the record of that pull. An hf.co/ ref
//     has no record at all (the controller records registry.ollama.ai tags
//     only), and no remedy.
//
// Three lanes read three stores (OllamaLaneContainer, OllamaLaneNative,
// OllamaLaneStack). The stack lane is the controller's own node adopting the
// stack's Ollama (noo-ollama-embed on a one-box): compose manages it, so the
// check reports and never repairs, and its remedy is the command that re-pulls
// into it, `noo models pull <tag>`.
//
// A store file the agent cannot read (EACCES) is its own state,
// OllamaCannotRead, never "no local manifest" or a hash failure: the agent
// reads the stack's store through its "other" permission bits, and an Ollama
// that wrote 0600 files would otherwise show as a fake mismatch.
//
// Hashing goes through a VerifiedRecord (verified/ollama-blobs.json in the
// agent's own state dir), so a re-check of unchanged blobs is a stat.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// Verification states, as the heartbeat's `ollama_verify` carries them.
const (
	OllamaVerified   = "verified"
	OllamaMismatch   = "mismatch"
	OllamaUnverified = "unverified"
	OllamaRebuilt    = "rebuilt"
	OllamaRefused    = "refused"
	OllamaVerifyErr  = "error"
	// OllamaCannotRead: a manifest or blob of the local store exists but
	// the agent may not read it (permission). Report only, with its own
	// remedy: nothing is known about the bytes.
	OllamaCannotRead = "cannot-read"
)

// The lane a verifier checks: which Ollama, and so which store. The adopted
// lanes carry backendrt.Native's Runtime() labels.
const (
	// OllamaLaneContainer: the agent's own noo-ollama container
	// (OLLAMA_DATA_DIR/models). Repaired from the controller.
	OllamaLaneContainer = ""
	// OllamaLaneNative: a host Ollama the operator runs (a Mac's). Report
	// only.
	OllamaLaneNative = "native"
	// OllamaLaneStack: the stack's Ollama on the controller's own node,
	// compose-managed. Report only.
	OllamaLaneStack = "stack"
)

// stackOllamaSource is the host directory compose binds as ollama-embed's
// (and ollama's) store: ${NOO_DATA_ROOT}/ollama (docker-compose.cluster.yml,
// volumes ollama-data and ollama-embed-data). It follows NOO_DATA_ROOT, NOT
// OLLAMA_DATA_DIR: that override is the agent's own container's.
var stackOllamaSource = dataRootSource + "/ollama"

// ollamaModelsDir is the models directory (manifests/ and blobs/) of the
// Ollama on lane.
func ollamaModelsDir(lane string) string {
	switch lane {
	case OllamaLaneNative:
		return nativeOllamaModelsDir()
	case OllamaLaneStack:
		return filepath.Join(resolveEnv(stackOllamaSource), "models")
	}
	return filepath.Join(resolveEnv(ollamaSource), "models")
}

// Anchors: what the controller's store vouches for the model with.
const (
	OllamaAnchorMirror = "mirror"
	OllamaAnchorGGUF   = "gguf"
	OllamaAnchorNone   = "none"
)

// OllamaVerifyResult is one model's row in the heartbeat's `ollama_verify`.
type OllamaVerifyResult struct {
	Model  string `json:"model"`
	State  string `json:"state"`
	Anchor string `json:"anchor"`
	// ModelLayer is the digest of the model layer the LOCAL manifest names
	// ("sha256:<hex>"), so the controller sees each node's weight digest.
	// Empty when the local manifest could not be read.
	ModelLayer string `json:"model_layer"`
	Reason     string `json:"reason"`
	Remedy     string `json:"remedy,omitempty"`
	// Lane is the verifier's lane when it is an adopted one ("native",
	// "stack"), so the verify row can say who repairs a mismatch.
	Lane      string `json:"lane,omitempty"`
	CheckedAt string `json:"checked_at"`
	// Blob is the offending digest of a mismatch (not on the wire: it is in
	// Reason already).
	Blob string `json:"-"`
}

// ollamaRemedy is the operator's fix for any model this check cannot vouch
// for, as a command that acts on THIS node's Ollama. `noo models pull` reaches
// only the gateway's Ollama, so it is the fix on the controller's own node
// (NOO_SELF_NODE) and nowhere else: another node gets the model staged on the
// controller and imported onto it (harrier, an artifact, by name). No command
// records a pull on another node.
func ollamaRemedy(model string) string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NOO_SELF_NODE"))) {
	case "1", "true", "yes":
		return "noo models pull " + model
	}
	node := strings.TrimSpace(os.Getenv("NODE_ID"))
	if node == "" || node == "auto" {
		node = "<this node>"
	}
	if model == "harrier" {
		return "noo cluster import-model " + node + " harrier"
	}
	return "noo models fetch ollama:" + model + " && noo cluster import-model " + node + " ollama:" + model
}

// OllamaVerifier checks placed models in one ollama store.
type OllamaVerifier struct {
	// ModelsDir is the host directory holding manifests/ and blobs/.
	ModelsDir string
	// Native: the agent does not manage this ollama (a Mac's own). Report
	// only: never repair, never refuse.
	Native bool
	// Lane is OllamaLaneContainer, OllamaLaneNative or OllamaLaneStack. The
	// stack lane is report-only too, and its remedy is `noo models pull`.
	Lane   string
	Record *preseed.VerifiedRecord

	// Seams (set by NewOllamaVerifier; replaced in tests).
	// lookup is the controller's artifact manifest sha256 for kind/name,
	// ErrArtifactAbsent when the store has none.
	lookup func(ctx context.Context, kind, name string) (string, error)
	// fetch returns the body of store artifact name, verified against sha.
	fetch func(ctx context.Context, name, sha string) ([]byte, error)
	// hash is the sha256 hex of a file on disk.
	hash func(path string) (string, error)
	// repair re-installs (mirror) or rebuilds (gguf) model from the
	// controller, first removing badBlobs (hex digests whose files exist but
	// do not hold those bytes: ollama skips a blob it already has by name).
	repair func(ctx context.Context, model, anchor string, badBlobs []string) error
	now    func() time.Time
}

// ollamaVerifyRecordPath is the record's file, beside hf-weights.json. A
// seam for tests.
var ollamaVerifyRecordPath = func() string {
	return filepath.Join(nodeconfig.Load().StateDir, "verified", "ollama-blobs.json")
}

// NewOllamaVerifier is the production verifier for this node's ollama on
// lane: the container's store (OLLAMA_DATA_DIR/models), the host ollama's
// models dir (native), or the stack's (${NOO_DATA_ROOT}/ollama/models).
func (c *Client) NewOllamaVerifier(lane string) *OllamaVerifier {
	models := ollamaModelsDir(lane)
	mounted := []string{resolveEnv(hfCacheSource), resolveEnv(modelsSource), resolveEnv(ollamaSource)}
	if lane != OllamaLaneContainer {
		mounted = append(mounted, models)
	}
	return &OllamaVerifier{
		ModelsDir: models,
		Native:    lane == OllamaLaneNative,
		Lane:      lane,
		Record:    preseed.OpenVerifiedRecord(ollamaVerifyRecordPath(), mounted...),
		lookup: func(ctx context.Context, kind, name string) (string, error) {
			m, err := lookupArtifactManifest(ctx, kind, name)
			if err != nil {
				return "", err
			}
			return m.SHA256, nil
		},
		fetch: fetchStoreArtifact,
		hash:  preseed.HashFile,
		repair: func(ctx context.Context, model, _ string, bad []string) error {
			return c.repairOllamaModel(ctx, model, bad)
		},
		now: time.Now,
	}
}

// fetchStoreArtifact downloads one small store artifact (a manifest or a
// Modelfile) into a temp dir, verified against sha, and returns its bytes.
func fetchStoreArtifact(ctx context.Context, name, sha string) ([]byte, error) {
	cacheURL := preseed.CacheURL()
	if cacheURL == "" {
		return nil, errors.New("NOO_MODEL_CACHE_URL is not set — no data plane to read the controller's record from")
	}
	if err := os.MkdirAll(stagingDir(), 0o755); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(stagingDir(), "ollama-verify-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(work) }()
	dest := filepath.Join(work, name)
	fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := preseed.New().FetchOneVerified(fctx, cacheURL+"/gguf/"+url.PathEscape(name), dest, sha); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(dest)
	if err != nil {
		return nil, err
	}
	if len(b) > mirrorMaxManifestBytes {
		return nil, fmt.Errorf("%s is %d bytes, over the %d limit", name, len(b), mirrorMaxManifestBytes)
	}
	return b, nil
}

// repairOllamaModel removes the blobs whose bytes are wrong (inside
// noo-ollama, as its own user) and runs the import path again: a mirror is
// re-installed, a Modelfile model rebuilt from its verified GGUF.
//
// A failure names the path the rebuild took (the container or the host
// binary, ollamaImportVia), so the refusal on the first heartbeat says where
// it failed, not only that it did.
func (c *Client) repairOllamaModel(ctx context.Context, model string, bad []string) error {
	if len(bad) > 0 {
		if err := c.removeOllamaBlobs(ctx, bad); err != nil {
			return fmt.Errorf("removing the bad blobs in %s: %w", OllamaContainer, err)
		}
	}
	via := c.ollamaImportVia(ctx)
	if _, err := c.PullOllamaModel(ctx, model); err != nil {
		return fmt.Errorf("the rebuild through %s: %w", via, err)
	}
	return nil
}

var blobHexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// removeOllamaBlobs deletes named blobs from the container's store. Every
// path is built from a validated 64-hex digest.
func (c *Client) removeOllamaBlobs(ctx context.Context, hexes []string) error {
	if c == nil || c.docker == nil {
		return errors.New("Docker is not available to remove the bad blobs from " + OllamaContainer)
	}
	root, _, err := c.ollamaContainerStore(ctx)
	if err != nil {
		return err
	}
	for _, h := range hexes {
		if !blobHexRe.MatchString(h) {
			return fmt.Errorf("refusing to remove blob %q: not a sha256 digest", h)
		}
		p := path.Join(root, "models", "blobs", "sha256-"+h)
		if _, err := c.execCaptureIn(ctx, OllamaContainer, "/", []string{"rm", "-f", p}, time.Minute); err != nil {
			return fmt.Errorf("remove the bad blob %s from %s: %w", h[:12], OllamaContainer, err)
		}
	}
	return nil
}

// localManifest is what the check reads of the local manifest.
type localManifest struct {
	Config string // "sha256:<hex>"
	Layers []manifestLayer
}

type manifestLayer struct{ Media, Digest string }

// readManifestDigests parses an ollama manifest's config and layer digests.
// Every digest must be sha256:<64 lowercase hex>: a blob path is built from
// it, and the local manifest is attacker-writable.
func readManifestDigests(body []byte) (*localManifest, error) {
	var m struct {
		Config *struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"layers"`
	}
	if len(body) > mirrorMaxManifestBytes {
		return nil, fmt.Errorf("manifest is %d bytes, over the %d limit", len(body), mirrorMaxManifestBytes)
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("manifest is not JSON: %w", err)
	}
	if m.Config == nil || !mirrorDigestRe.MatchString(m.Config.Digest) {
		return nil, errors.New("manifest has no usable config digest")
	}
	out := &localManifest{Config: m.Config.Digest}
	for i, l := range m.Layers {
		if !mirrorDigestRe.MatchString(l.Digest) {
			return nil, fmt.Errorf("manifest layer %d digest %q is not sha256:<64 hex>", i, l.Digest)
		}
		out.Layers = append(out.Layers, manifestLayer{Media: l.MediaType, Digest: l.Digest})
	}
	return out, nil
}

// modelLayers are the layers ollama loads weights from.
func (m *localManifest) modelLayers() []string {
	var out []string
	for _, l := range m.Layers {
		if strings.HasSuffix(l.Media, ".model") {
			out = append(out, l.Digest)
		}
	}
	return out
}

// reportOnly: the agent does not manage this Ollama (a native one, or the
// stack's), so a mismatch is reported and nothing is removed or re-installed.
func (v *OllamaVerifier) reportOnly() bool {
	return v.Native || v.Lane == OllamaLaneStack
}

// remedy is the operator's fix for model on this verifier's Ollama. On the
// stack lane that is the re-pull into the stack's Ollama, which also
// rewrites the controller's record of the pull.
func (v *OllamaVerifier) remedy(model string) string {
	if v.Lane == OllamaLaneStack {
		return "noo models pull " + model
	}
	return ollamaRemedy(model)
}

// unreadableErr is a local store file the agent may not read (EACCES): a
// state of its own (OllamaCannotRead), never "absent" and never a verdict.
type unreadableErr struct {
	path string
	err  error
}

func (e *unreadableErr) Error() string { return "cannot read " + e.path + ": " + e.err.Error() }
func (e *unreadableErr) Unwrap() error { return e.err }

// localRead marks a permission error on path as unreadableErr; any other
// error passes through.
func localRead(path string, err error) error {
	if err != nil && errors.Is(err, fs.ErrPermission) {
		return &unreadableErr{path: path, err: err}
	}
	return err
}

// agentUser names the account this agent reads the store as.
func agentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return fmt.Sprintf("uid %d", os.Getuid())
}

// ollamaUnreadableFallback joins a cannot-read remedy's re-pull to its
// fallback; the CLI's verify row splits on it.
const ollamaUnreadableFallback = "; if the files stay unreadable: "

// cannotRead is the result for a store file the agent may not read.
//
// The store is readable as shipped: our Ollama image writes it with umask
// 0022 (directories 755, files 644; measured on Ollama 0.40.16), and the
// agent reads it through the "other" bits. A 0600 file usually means
// something other than our image wrote it, or the umask was changed. So the
// remedy leads with the re-pull through noo (Ollama rewrites the blobs and
// the manifest with its own modes), and the chmod, which needs sudo, is
// only the fallback.
func (v *OllamaVerifier) cannotRead(res OllamaVerifyResult, model string, ue *unreadableErr) OllamaVerifyResult {
	res.State = OllamaCannotRead
	res.Reason = fmt.Sprintf("cannot read %s as %s (permission denied): the agent reads this store through its \"other\" permission bits and this file grants none, so its bytes are not checked; our Ollama image writes the store 755/644 (umask 0022), so the file was likely written by something else or under a changed umask",
		ue.path, agentUser())
	res.Remedy = v.remedy(model) + ollamaUnreadableFallback + "sudo chmod -R o+rX " + v.ModelsDir
	return res
}

func (v *OllamaVerifier) manifestPath(ns, name, tag string) string {
	return filepath.Join(v.ModelsDir, "manifests", "registry.ollama.ai", ns, name, tag)
}

func (v *OllamaVerifier) blobPath(hex string) string {
	return filepath.Join(v.ModelsDir, "blobs", "sha256-"+hex)
}

type blobVerdict int

const (
	blobOK blobVerdict = iota
	blobMissing
	blobBad // exists, bytes are not the digest
)

// checkBlob: does the store's file for hex hold those bytes? Through the
// record: a hit (same dev, inode, size, mtime, ctime as when this node last
// hashed it) is a stat; anything else is hashed.
func (v *OllamaVerifier) checkBlob(hex string) (blobVerdict, error) {
	p := v.blobPath(hex)
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return blobMissing, nil
	}
	if err != nil {
		return 0, localRead(p, err)
	}
	if !fi.Mode().IsRegular() {
		return blobBad, nil
	}
	if v.Record.Verified(p, hex) {
		return blobOK, nil
	}
	got, err := v.hash(p)
	if err != nil {
		v.Record.Forget(p)
		return 0, localRead(p, err)
	}
	if got != hex {
		v.Record.Forget(p)
		return blobBad, nil
	}
	v.Record.Remember(p, hex)
	return blobOK, nil
}

// anchorRef is what the controller's store vouches for the model with.
type anchorRef struct {
	kind string
	// mirror: the ollamamanifest artifact; gguf: the Modelfile artifact.
	name, sha string
}

// resolveAnchor asks the store in the order PullOllamaModel installs from:
// a plain <name>.Modelfile, else the staged mirror, else the staged
// <stem>.Modelfile. An unanswered question is an error, never "none".
func (v *OllamaVerifier) resolveAnchor(ctx context.Context, name string) (anchorRef, error) {
	cands, err := storeCandidates(name)
	if err != nil {
		return anchorRef{kind: OllamaAnchorNone}, nil
	}
	ask := func(kind, art string) (string, bool, error) {
		sha, err := v.lookup(ctx, kind, art)
		switch {
		case err == nil:
			return sha, true, nil
		case errors.Is(err, ErrArtifactAbsent), errors.Is(err, ErrArtifactKindUnknown):
			return "", false, nil
		}
		return "", false, fmt.Errorf("could not ask the controller for %s/%s: %w", kind, art, err)
	}
	if !cands[0].staged {
		sha, ok, err := ask("modelfile", cands[0].base+".Modelfile")
		if err != nil {
			return anchorRef{}, err
		}
		if ok {
			return anchorRef{kind: OllamaAnchorGGUF, name: cands[0].base + ".Modelfile", sha: sha}, nil
		}
	}
	if r, ok := mirrorRefOf(name); ok {
		mf := r.stem + mirrorManifestSuffix
		sha, ok, err := ask("ollamamanifest", mf)
		if err != nil {
			return anchorRef{}, err
		}
		if ok {
			return anchorRef{kind: OllamaAnchorMirror, name: mf, sha: sha}, nil
		}
	}
	for _, cd := range cands {
		if !cd.staged {
			continue
		}
		sha, ok, err := ask("modelfile", cd.base+".Modelfile")
		if err != nil {
			return anchorRef{}, err
		}
		if ok {
			return anchorRef{kind: OllamaAnchorGGUF, name: cd.base + ".Modelfile", sha: sha}, nil
		}
	}
	return anchorRef{kind: OllamaAnchorNone}, nil
}

// finding is one pass of the check, before any repair.
type finding struct {
	ok         bool
	reason     string
	blob       string   // offending digest, "sha256:<hex>"
	bad        []string // hexes whose files exist with the wrong bytes
	missing    []string // hexes the anchor names whose files are absent
	modelLayer string
}

// Verify checks model and, on a mismatch where the agent manages ollama,
// repairs it from the controller; a failed repair is a refusal.
func (v *OllamaVerifier) Verify(ctx context.Context, model string) OllamaVerifyResult {
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	res := OllamaVerifyResult{Model: model, Anchor: OllamaAnchorNone, Lane: v.Lane, CheckedAt: now().UTC().Format(time.RFC3339)}
	name := strings.TrimPrefix(strings.TrimSpace(model), "ollama:")
	if strings.HasPrefix(strings.ToLower(name), "hf.co/") {
		// Not a registry.ollama.ai tag: nothing records it, and a re-pull
		// would not either, so no remedy is offered.
		res.State, res.Reason = OllamaUnverified, "hf.co refs have no controller record"
		return res
	}
	ns, n, tag, err := parseOllamaRef(name)
	if err != nil {
		res.State, res.Reason = OllamaVerifyErr, err.Error()
		return res
	}
	mpath := v.manifestPath(ns, n, tag)
	a, err := v.resolveAnchor(ctx, name)
	if err != nil {
		// Unanswered is not "no record": report, never refuse on it.
		res.State, res.Reason = OllamaVerifyErr, err.Error()
		res.ModelLayer = localModelLayer(mpath)
		return res
	}
	res.Anchor = a.kind
	if a.kind == OllamaAnchorNone {
		res.State, res.Reason, res.Remedy = OllamaUnverified, "no controller record", v.remedy(model)
		res.ModelLayer = localModelLayer(mpath)
		return res
	}
	f, err := v.check(ctx, a, mpath)
	if err != nil {
		res.ModelLayer = localModelLayer(mpath)
		var ue *unreadableErr
		if errors.As(err, &ue) {
			return v.cannotRead(res, model, ue)
		}
		res.State, res.Reason = OllamaVerifyErr, err.Error()
		return res
	}
	res.ModelLayer = f.modelLayer
	if f.ok {
		res.State, res.Reason = OllamaVerified, "matches the controller's "+anchorWhat(a.kind)
		return res
	}
	res.Blob = f.blob
	if v.reportOnly() {
		// Not ours to touch: the operator's ollama, or the stack's
		// (compose-managed). Report only: no blob is removed, nothing is
		// re-installed.
		res.State, res.Reason, res.Remedy = OllamaMismatch, f.reason, v.remedy(model)
		return res
	}
	verb := "re-installing it from the controller's mirror"
	if a.kind == OllamaAnchorGGUF {
		verb = "rebuilding it from the controller's verified GGUF"
	}
	if a.kind == OllamaAnchorMirror {
		// A record of a pull holds no bytes: refuse before removing anything.
		if h := v.storeLacksBytes(ctx, f); h != "" {
			res.State, res.Remedy = OllamaRefused, ollamaRemedy(model)
			res.Reason = fmt.Sprintf("%s: blob %s does not match the controller's record (%s), and this model's record is the controller's record of its pull, with no bytes to repair from (the store has no blob sha256:%s) — run `%s`",
				model, f.blob, f.reason, h[:12], res.Remedy)
			return res
		}
	}
	if v.repair == nil {
		return v.refuse(res, model, f, verb, errors.New("no repair path on this agent"))
	}
	if rerr := v.repair(ctx, model, a.kind, f.bad); rerr != nil {
		return v.refuse(res, model, f, verb, rerr)
	}
	g, err := v.check(ctx, a, mpath)
	if err != nil {
		return v.refuse(res, model, f, verb, fmt.Errorf("it could not be re-checked: %w", err))
	}
	res.ModelLayer = g.modelLayer
	if !g.ok {
		res.Blob = g.blob
		return v.refuse(res, model, g, verb, errors.New("it still does not match afterwards: "+g.reason))
	}
	res.State = OllamaRebuilt
	res.Reason = f.reason + "; repaired by " + verb
	return res
}

func (v *OllamaVerifier) refuse(res OllamaVerifyResult, model string, f finding, verb string, err error) OllamaVerifyResult {
	res.State = OllamaRefused
	res.Remedy = ollamaRemedy(model)
	res.Reason = fmt.Sprintf("%s: blob %s does not match the controller's record (%s), and %s failed: %v — run `%s`",
		model, f.blob, f.reason, verb, err, res.Remedy)
	return res
}

// storeLacksBytes is the first blob a mirror repair would need from the
// controller's store (one this node lacks, or holds with the wrong bytes)
// that the store does not hold, "" when it holds them all. A question the
// store did not answer is not "absent": the repair is tried and says why.
func (v *OllamaVerifier) storeLacksBytes(ctx context.Context, f finding) string {
	for _, h := range append(append([]string(nil), f.bad...), f.missing...) {
		_, err := v.lookup(ctx, "ollamablob", mirrorBlob{Hex: h}.blobName())
		if errors.Is(err, ErrArtifactAbsent) {
			return h
		}
	}
	return ""
}

func anchorWhat(kind string) string {
	if kind == OllamaAnchorGGUF {
		return "GGUF"
	}
	return "record of its pull"
}

// localModelLayer is the model-layer digest the local manifest names, "" if
// it cannot be read. Report-only.
func localModelLayer(mpath string) string {
	b, err := os.ReadFile(mpath)
	if err != nil {
		return ""
	}
	lm, err := readManifestDigests(b)
	if err != nil {
		return ""
	}
	if ml := lm.modelLayers(); len(ml) > 0 {
		return ml[0]
	}
	return ""
}

// check runs one comparison of the local store against the anchor. An error
// is a failure to read the CONTROLLER's side (or a local read error that is
// not "absent"), never a verdict.
func (v *OllamaVerifier) check(ctx context.Context, a anchorRef, mpath string) (finding, error) {
	body, err := v.fetch(ctx, a.name, a.sha)
	if err != nil {
		return finding{}, fmt.Errorf("could not read the controller's %s: %w", a.name, err)
	}
	lb, lerr := os.ReadFile(mpath)
	if lerr != nil && !errors.Is(lerr, os.ErrNotExist) {
		return finding{}, fmt.Errorf("read the local manifest: %w", localRead(mpath, lerr))
	}
	var lm *localManifest
	var lmErr error
	if lerr == nil {
		lm, lmErr = readManifestDigests(lb)
	}
	var f finding
	if lm != nil {
		if ml := lm.modelLayers(); len(ml) > 0 {
			f.modelLayer = ml[0]
		}
	}
	switch a.kind {
	case OllamaAnchorMirror:
		return v.checkMirror(body, lm, lerr, lmErr, f)
	default:
		return v.checkGGUF(ctx, a, body, lm, lerr, lmErr, f)
	}
}

func (v *OllamaVerifier) checkMirror(body []byte, lm *localManifest, lerr, lmErr error, f finding) (finding, error) {
	cm, err := parseMirrorManifest(body)
	if err != nil {
		return finding{}, fmt.Errorf("the controller's mirrored manifest: %w", err)
	}
	ctl, err := readManifestDigests(body)
	if err != nil {
		return finding{}, fmt.Errorf("the controller's mirrored manifest: %w", err)
	}
	// Every blob the controller's manifest names is hashed, whatever the
	// local manifest says: a repair must know which files hold wrong bytes.
	var firstMissing string
	for _, b := range cm.Blobs {
		vd, err := v.checkBlob(b.Hex)
		if err != nil {
			return finding{}, fmt.Errorf("hash blob %s: %w", b.short(), err)
		}
		switch vd {
		case blobBad:
			f.bad = append(f.bad, b.Hex)
		case blobMissing:
			if firstMissing == "" {
				firstMissing = "sha256:" + b.Hex
			}
			f.missing = append(f.missing, b.Hex)
		}
	}
	switch {
	case lerr != nil:
		f.reason, f.blob = "no local manifest", "sha256:"+cm.Blobs[0].Hex
		return f, nil
	case lmErr != nil:
		f.reason, f.blob = "the local manifest is unreadable: "+lmErr.Error(), "sha256:"+cm.Blobs[0].Hex
		return f, nil
	}
	if lm.Config != ctl.Config {
		f.reason, f.blob = "the local manifest's config is "+lm.Config+", the controller's is "+ctl.Config, lm.Config
		return f, nil
	}
	want := digestSet(ctl.Layers)
	have := digestSet(lm.Layers)
	for _, d := range sortedKeys(have) {
		if !want[d] {
			// The attacker case: a blob the controller never named, however
			// well it hashes to its own name.
			f.reason, f.blob = "the local manifest names layer "+d+", which the controller's does not", d
			return f, nil
		}
	}
	for _, d := range sortedKeys(want) {
		if !have[d] {
			f.reason, f.blob = "the local manifest lacks layer "+d+", which the controller's names", d
			return f, nil
		}
	}
	if len(f.bad) > 0 {
		f.reason, f.blob = "the blob's bytes do not hash to its digest", "sha256:"+f.bad[0]
		return f, nil
	}
	if firstMissing != "" {
		f.reason, f.blob = "the blob is missing from the store", firstMissing
		return f, nil
	}
	f.ok = true
	return f, nil
}

// checkGGUF anchors the MODEL layer only. The Modelfile's other layers
// (template, system, params, license, messages) are NOT anchored in v1: the
// controller publishes the Modelfile but not the digests ollama gives the
// layers `ollama create` derives from it, so there is nothing to compare
// them with. The weights — the bytes that make the model — are.
func (v *OllamaVerifier) checkGGUF(ctx context.Context, a anchorRef, body []byte, lm *localManifest, lerr, lmErr error, f finding) (finding, error) {
	weight, err := modelfileWeight(string(body))
	if err != nil {
		return finding{}, fmt.Errorf("the controller's %s: %w", a.name, err)
	}
	gsha, err := v.lookup(ctx, "gguf", weight)
	if err != nil {
		return finding{}, fmt.Errorf("could not get the controller's sha256 for %s: %w", weight, err)
	}
	gsha = strings.ToLower(gsha)
	if !blobHexRe.MatchString(gsha) {
		return finding{}, fmt.Errorf("the controller's sha256 for %s is %q, not 64 hex", weight, gsha)
	}
	want := "sha256:" + gsha
	vd, err := v.checkBlob(gsha)
	if err != nil {
		return finding{}, fmt.Errorf("hash blob %s: %w", gsha[:12], err)
	}
	if vd == blobBad {
		f.bad = []string{gsha}
	}
	switch {
	case lerr != nil:
		f.reason, f.blob = "no local manifest", want
		return f, nil
	case lmErr != nil:
		f.reason, f.blob = "the local manifest is unreadable: "+lmErr.Error(), want
		return f, nil
	}
	ml := lm.modelLayers()
	if len(ml) != 1 {
		f.reason, f.blob = fmt.Sprintf("the local manifest names %d model layers, want exactly 1", len(ml)), want
		return f, nil
	}
	if ml[0] != want {
		f.reason, f.blob = "the local model layer is "+ml[0]+", the controller's "+weight+" is "+want, ml[0]
		return f, nil
	}
	switch vd {
	case blobBad:
		f.reason, f.blob = "the blob's bytes do not hash to its digest", want
		return f, nil
	case blobMissing:
		f.reason, f.blob = "the blob is missing from the store", want
		return f, nil
	}
	f.ok = true
	return f, nil
}

func digestSet(ls []manifestLayer) map[string]bool {
	out := map[string]bool{}
	for _, l := range ls {
		out[l.Digest] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
