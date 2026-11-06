// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import (
	"regexp"
	"strings"
	"time"
)

// FormatModelSet is the `format` of a model-set.json.
const FormatModelSet = "noo-model-set/1"

// Refusal codes of ParseModelSet, beside the shared ones in errors.go.
const (
	CodeIDInvalid          = "id_invalid"
	CodeRevisionInvalid    = "revision_invalid"
	CodeKindInvalid        = "kind_invalid"
	CodeModalityInvalid    = "modality_invalid"
	CodeRuntimeInvalid     = "runtime_invalid"
	CodeSourceInvalid      = "source_invalid"
	CodeLicenseInvalid     = "license_invalid"
	CodePathInvalid        = "path_invalid"
	CodeSHA256Invalid      = "sha256_invalid"
	CodeFilesInvalid       = "files_invalid"
	CodeFromArchiveInvalid = "from_archive_invalid"
	CodeNoticeNotInFiles   = "notice_not_in_files"
	CodeProfileInvalid     = "profile_invalid"
	CodeArchInvalid        = "arch_invalid"
	CodeFitsRequired       = "fits_required"
	CodeFitsForbidden      = "fits_forbidden"
	CodeFitsInvalid        = "fits_invalid"
	CodeTrustRequired      = "trust_required"
	CodeTrustInvalid       = "trust_invalid"
	digestsAuthenticated   = "authenticated"
	digestsOperatorTrust   = "operator-trusted-local"
	maxSetFiles            = 64
	maxSetFileBytes        = int64(1) << 40
)

var (
	setProfileRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	computeRe    = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]$`)
	sha256Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRe     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hfRepoRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	licenseIDRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	httpsURLRe   = regexp.MustCompile(`^https://\S{1,500}$`)
	fileCompRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// ModelSet is a validated model-set.json. The signature is a separate
// detached file and is checked before this parse runs, over the exact bytes.
type ModelSet struct {
	Format   string   `json:"format"`
	ID       string   `json:"id"`
	Revision string   `json:"revision"`
	Kind     string   `json:"kind"`
	Modality string   `json:"modality"`
	Runtime  []string `json:"runtime"`
	Source   Source   `json:"source"`
	License  License  `json:"license"`
	Files    []File   `json:"files"`
	Needs    Needs    `json:"needs"`
	Fits     *Fits    `json:"fits,omitempty"`
	Trust    *Trust   `json:"trust,omitempty"`
}

type Source struct {
	HF    *HFSource    `json:"hf,omitempty"`
	Local *LocalSource `json:"local,omitempty"`
}

type HFSource struct {
	Repo    string `json:"repo"`
	Ref     string `json:"ref"`
	Digests string `json:"digests"`
}

type LocalSource struct {
	Verified bool `json:"verified"`
}

type License struct {
	ID          string       `json:"id"`
	URL         string       `json:"url"`
	Accept      string       `json:"accept"`
	Accepted    *Accepted    `json:"accepted,omitempty"`
	NoticeFiles []string     `json:"notice_files,omitempty"`
	Additional  []Additional `json:"additional,omitempty"`
}

type Accepted struct {
	By string `json:"by"`
	At string `json:"at"`
}

type Additional struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	NoticePath string `json:"notice_path,omitempty"`
}

type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role,omitempty"`
	// FromArchive says the controller extracted this file from an archive of
	// the same upstream repo and revision at staging. Nodes only ever see the
	// flat, verified file; the archive itself is not part of the set.
	FromArchive *FromArchive `json:"from_archive,omitempty"`
}

// FromArchive names the archive a file was extracted from, and the archive's
// own digest and size.
type FromArchive struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Needs struct {
	Profiles    []Profile `json:"profiles"`
	CPUFallback bool      `json:"cpu_fallback"`
	Arch        []string  `json:"arch"`
}

type Profile struct {
	Name          string `json:"name"`
	Accel         string `json:"accel"`
	MinCompute    string `json:"min_compute,omitempty"`
	VRAMMB        *int64 `json:"vram_mb,omitempty"`
	RAMMB         *int64 `json:"ram_mb,omitempty"`
	PerSlotVRAMMB *int64 `json:"per_slot_vram_mb,omitempty"`
	Realtime      *bool  `json:"realtime,omitempty"`
}

type Fits struct {
	Model    string `json:"model,omitempty"`
	Revision string `json:"revision,omitempty"`
	Runtime  string `json:"runtime,omitempty"`
}

type Trust struct {
	By     string `json:"by"`
	At     string `json:"at"`
	Reason string `json:"reason"`
}

// ValidSetRef reports whether id and revision match the schema patterns. The
// node checks a ref with it before the ref becomes a URL or a path.
func ValidSetRef(id, revision string) bool {
	return setIDRe.MatchString(id) && setRevRe.MatchString(revision)
}

// ValidSetPath is the file path rule of a model set: relative, no `.` or `..`
// component, at most one directory level, charset [A-Za-z0-9._-]. It is the
// rule the rail's path check and the node's mount check must share.
func ValidSetPath(p string) bool {
	if p == "" || len(p) > 129 {
		return false
	}
	comps := strings.Split(p, "/")
	if len(comps) > 2 {
		return false
	}
	for _, c := range comps {
		if c == "" || c == "." || c == ".." || !fileCompRe.MatchString(c) {
			return false
		}
	}
	return true
}

// ParseModelSet validates a model-set.json (after its signature has been
// verified over these exact bytes). The first refusal wins.
func ParseModelSet(b []byte) (*ModelSet, error) {
	var m ModelSet
	if err := decodeStrict(b, &m, nullableModelSet); err != nil {
		return nil, err
	}
	g := generic(b)
	if err := requireKeys(g, "model-set.json", "format", "id", "revision", "kind", "modality", "runtime", "source", "license", "files", "needs"); err != nil {
		return nil, err
	}
	// The url key ends its line: tests/test_url_userinfo_scrub.py reads a
	// quoted url key followed by a value on the same line as a log call.
	required := [][]string{
		{"license", "id", "url",
			"accept"},
		{"needs", "profiles", "cpu_fallback", "arch"},
	}
	for _, sub := range required {
		if err := requireKeys(field(g, sub[0]), sub[0], sub[1:]...); err != nil {
			return nil, err
		}
	}
	src := field(g, "source")
	if err := requireKeys(field(src, "hf"), "source.hf", "repo", "ref", "digests"); err != nil {
		return nil, err
	}
	if err := requireKeys(field(src, "local"), "source.local", "verified"); err != nil {
		return nil, err
	}
	for _, f := range items(g, "files") {
		if err := requireKeys(f, "files[]", "path", "bytes", "sha256"); err != nil {
			return nil, err
		}
		if err := requireKeys(field(f, "from_archive"), "files[].from_archive", "path", "sha256", "bytes"); err != nil {
			return nil, err
		}
	}
	for _, p := range items(field(g, "needs"), "profiles") {
		if err := requireKeys(p, "needs.profiles[]", "name", "accel"); err != nil {
			return nil, err
		}
	}
	if err := checkSet(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func checkSet(m *ModelSet) error {
	if m.Format != FormatModelSet {
		return fail(CodeBadFormat, "format is %q, want %q", m.Format, FormatModelSet)
	}
	if !setIDRe.MatchString(m.ID) {
		return fail(CodeIDInvalid, "id %q", m.ID)
	}
	if !setRevRe.MatchString(m.Revision) {
		return fail(CodeRevisionInvalid, "revision %q", m.Revision)
	}
	if m.Kind != "voice" && m.Kind != "voice-pack" {
		return fail(CodeKindInvalid, "kind %q", m.Kind)
	}
	switch m.Modality {
	case "speech-to-speech", "stt", "tts":
	default:
		return fail(CodeModalityInvalid, "modality %q", m.Modality)
	}
	if len(m.Runtime) < 1 || len(m.Runtime) > 8 {
		return fail(CodeRuntimeInvalid, "%d runtime strings (1..8)", len(m.Runtime))
	}
	for _, r := range m.Runtime {
		if !runtimeRe.MatchString(r) {
			return fail(CodeRuntimeInvalid, "runtime %q", r)
		}
	}
	if err := checkSource(m.Source); err != nil {
		return err
	}
	if err := checkLicense(m.License); err != nil {
		return err
	}
	if err := checkFiles(m.Files, m.License); err != nil {
		return err
	}
	if err := checkNeeds(m.Needs); err != nil {
		return err
	}
	if err := checkFits(m); err != nil {
		return err
	}
	return checkTrust(m)
}

func checkSource(s Source) error {
	if (s.HF == nil) == (s.Local == nil) {
		return fail(CodeSourceInvalid, "source takes exactly one of hf and local")
	}
	if s.HF != nil {
		if !hfRepoRe.MatchString(s.HF.Repo) || !commitRe.MatchString(s.HF.Ref) {
			return fail(CodeSourceInvalid, "source.hf needs repo <org>/<name> and a 40-hex commit ref")
		}
		if s.HF.Digests != digestsAuthenticated && s.HF.Digests != digestsOperatorTrust {
			return fail(CodeSourceInvalid, "source.hf.digests %q", s.HF.Digests)
		}
	}
	return nil
}

func rfc3339(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func checkLicense(l License) error {
	if !licenseIDRe.MatchString(l.ID) || !httpsURLRe.MatchString(l.URL) {
		return fail(CodeLicenseInvalid, "license id or url")
	}
	if l.Accept != "none" && l.Accept != "operator" {
		return fail(CodeLicenseInvalid, "license.accept %q", l.Accept)
	}
	if l.Accepted != nil && (l.Accept == "none" || l.Accepted.By == "" || len(l.Accepted.By) > 128 || !rfc3339(l.Accepted.At)) {
		return fail(CodeLicenseInvalid, "license.accepted needs accept=operator, by and an RFC 3339 at")
	}
	if len(l.Additional) > 8 {
		return fail(CodeLicenseInvalid, "%d additional licenses (at most 8)", len(l.Additional))
	}
	for _, a := range l.Additional {
		if !licenseIDRe.MatchString(a.ID) || !httpsURLRe.MatchString(a.URL) {
			return fail(CodeLicenseInvalid, "license.additional id or url")
		}
	}
	return nil
}

func checkFiles(files []File, lic License) error {
	notices := lic.NoticeFiles
	if len(files) < 1 || len(files) > maxSetFiles {
		return fail(CodeFilesInvalid, "%d files (1..%d)", len(files), maxSetFiles)
	}
	have := map[string]bool{}
	role := map[string]string{}
	for _, f := range files {
		if !ValidSetPath(f.Path) {
			return fail(CodePathInvalid, "file path %q", f.Path)
		}
		if !sha256Re.MatchString(f.SHA256) {
			return fail(CodeSHA256Invalid, "%s: sha256 is not 64 lower-case hex", f.Path)
		}
		if f.Bytes < 1 || f.Bytes > maxSetFileBytes {
			return fail(CodeFilesInvalid, "%s: bytes %d", f.Path, f.Bytes)
		}
		switch f.Role {
		case "", "weights", "notice", "config":
		default:
			return fail(CodeFilesInvalid, "%s: role %q", f.Path, f.Role)
		}
		if a := f.FromArchive; a != nil {
			if !ValidSetPath(a.Path) || !sha256Re.MatchString(a.SHA256) || a.Bytes < 1 || a.Bytes > maxSetFileBytes {
				return fail(CodeFromArchiveInvalid, "%s: from_archive needs a set path, a lower-case sha256 and bytes", f.Path)
			}
			if f.Role == "notice" {
				return fail(CodeFromArchiveInvalid, "%s: a notice file is staged as itself, not extracted from an archive", f.Path)
			}
		}
		if have[f.Path] {
			return fail(CodeFilesInvalid, "path %q is listed twice", f.Path)
		}
		have[f.Path] = true
		role[f.Path] = f.Role
	}
	for _, a := range lic.Additional {
		if a.NoticePath == "" {
			continue
		}
		if !ValidSetPath(a.NoticePath) {
			return fail(CodePathInvalid, "license.additional %s: notice_path %q", a.ID, a.NoticePath)
		}
		if role[a.NoticePath] != "notice" {
			return fail(CodeNoticeNotInFiles, "license.additional %s: notice_path %q is not a role notice file in files", a.ID, a.NoticePath)
		}
	}
	if len(notices) > 16 {
		return fail(CodeLicenseInvalid, "%d notice files (at most 16)", len(notices))
	}
	for _, n := range notices {
		if !ValidSetPath(n) {
			return fail(CodePathInvalid, "notice path %q", n)
		}
		if !have[n] {
			return fail(CodeNoticeNotInFiles, "license.notice_files names %q, which is not in files", n)
		}
	}
	return nil
}

func checkNeeds(n Needs) error {
	if len(n.Profiles) < 1 || len(n.Profiles) > 8 {
		return fail(CodeProfileInvalid, "%d profiles (1..8)", len(n.Profiles))
	}
	for _, p := range n.Profiles {
		if !setProfileRe.MatchString(p.Name) || (p.Accel != "cuda" && p.Accel != "cpu") {
			return fail(CodeProfileInvalid, "profile %q: name or accel", p.Name)
		}
		if p.MinCompute != "" && !computeRe.MatchString(p.MinCompute) {
			return fail(CodeProfileInvalid, "profile %q: min_compute %q", p.Name, p.MinCompute)
		}
		for _, v := range []*int64{p.VRAMMB, p.RAMMB, p.PerSlotVRAMMB} {
			if v != nil && (*v < 1 || *v > 4194304) {
				return fail(CodeProfileInvalid, "profile %q: a size is out of range", p.Name)
			}
		}
	}
	if len(n.Arch) < 1 || len(n.Arch) > 4 {
		return fail(CodeArchInvalid, "%d arch entries (1..4)", len(n.Arch))
	}
	for _, a := range n.Arch {
		if a != "amd64" && a != "arm64" {
			return fail(CodeArchInvalid, "arch %q", a)
		}
	}
	return nil
}

func checkFits(m *ModelSet) error {
	if m.Kind == "voice-pack" && m.Fits == nil {
		return fail(CodeFitsRequired, "a voice-pack states what it fits")
	}
	if m.Kind != "voice-pack" && m.Fits != nil {
		return fail(CodeFitsForbidden, "fits is for voice-pack only")
	}
	f := m.Fits
	if f == nil {
		return nil
	}
	byModel, byRuntime := f.Model != "", f.Runtime != ""
	if byModel == byRuntime || (byRuntime && f.Revision != "") {
		return fail(CodeFitsInvalid, "fits is {model[, revision]} or {runtime}")
	}
	if byModel && (!setIDRe.MatchString(f.Model) || (f.Revision != "" && !setRevRe.MatchString(f.Revision))) {
		return fail(CodeFitsInvalid, "fits.model or fits.revision is malformed")
	}
	if byRuntime && !runtimeRe.MatchString(f.Runtime) {
		return fail(CodeFitsInvalid, "fits.runtime is malformed")
	}
	return nil
}

func checkTrust(m *ModelSet) error {
	needs := (m.Source.HF != nil && m.Source.HF.Digests == digestsOperatorTrust) ||
		(m.Source.Local != nil && !m.Source.Local.Verified)
	if needs && m.Trust == nil {
		return fail(CodeTrustRequired, "digests were not authenticated upstream: trust {by, at, reason} is required")
	}
	if t := m.Trust; t != nil && (t.By == "" || len(t.By) > 128 || t.Reason == "" || len(t.Reason) > 500 || !rfc3339(t.At)) {
		return fail(CodeTrustInvalid, "trust needs by, an RFC 3339 at and a reason")
	}
	return nil
}
