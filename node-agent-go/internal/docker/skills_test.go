// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestValidateSkillFilesTraversal(t *testing.T) {
	bad := map[string]string{
		"../evil.py":           b64("x"),
		"..":                   b64("x"),
		"/etc/passwd":          b64("x"),
		"a/../../evil.py":      b64("x"),
		"a/./b.py":             b64("x"), // non-canonical
		".":                    b64("x"),
		"":                     b64("x"),
		"a\\b.py":              b64("x"),
		"subdir/../../evil.py": b64("x"),
		"./run.py":             b64("x"), // non-canonical
	}
	for name, content := range bad {
		if err := ValidateSkillFiles(map[string]string{name: content}); err == nil {
			t.Errorf("expected rejection for path %q", name)
		}
	}

	ok := map[string]string{
		"run.py":         b64("print('hi')"),
		"manifest.yml":   b64("name: x"),
		"lib/helpers.py": b64("pass"),
		"deep/a/b/c.txt": b64("data"),
		"weird..name.py": b64("pass"), // dots in name but no traversal
	}
	for name, content := range ok {
		if err := ValidateSkillFiles(map[string]string{name: content}); err != nil {
			t.Errorf("expected accepted for path %q: %v", name, err)
		}
	}
}

func TestValidateSkillFilesCountCap(t *testing.T) {
	files := make(map[string]string, MaxSkillFiles+1)
	for i := 0; i <= MaxSkillFiles; i++ {
		files["f"+strings.Repeat("a", i%10)+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+".txt"] = b64("x")
	}
	// Ensure we actually exceeded the cap (map key collisions would shrink it)
	for i := len(files); i <= MaxSkillFiles; i++ {
		files[strings.Repeat("z", i+1)+".txt"] = b64("x")
	}
	if len(files) <= MaxSkillFiles {
		t.Fatalf("test setup: only %d files", len(files))
	}
	if err := ValidateSkillFiles(files); err == nil {
		t.Error("expected count-cap rejection")
	}
}

func TestValidateSkillFilesSizeCap(t *testing.T) {
	// Two files of ~3MB each exceed the 5MB total decoded cap.
	big := strings.Repeat("A", 3*1024*1024)
	files := map[string]string{
		"a.bin": b64(big),
		"b.bin": b64(big),
	}
	if err := ValidateSkillFiles(files); err == nil {
		t.Error("expected size-cap rejection")
	}
	// A single 3MB file is fine.
	if err := ValidateSkillFiles(map[string]string{"a.bin": b64(big)}); err != nil {
		t.Errorf("expected 3MB single file accepted: %v", err)
	}
}

func TestValidateSkillFilesBadBase64(t *testing.T) {
	if err := ValidateSkillFiles(map[string]string{"run.py": "not-base64!!!"}); err == nil {
		t.Error("expected base64 rejection")
	}
}

func TestValidateSkillFilesEmpty(t *testing.T) {
	if err := ValidateSkillFiles(nil); err != nil {
		t.Errorf("nil files should validate: %v", err)
	}
	if err := ValidateSkillFiles(map[string]string{}); err != nil {
		t.Errorf("empty files should validate: %v", err)
	}
}

func TestBuildSkillFilesArchive(t *testing.T) {
	files := map[string]string{
		"run.py":         b64("print('hello')"),
		"manifest.yml":   b64("name: text_summarizer"),
		"lib/helpers.py": b64("def f(): pass"),
	}
	buf, err := buildSkillFilesArchive(files)
	if err != nil {
		t.Fatalf("build archive: %v", err)
	}

	// Read the tar back: every regular file must live under skill/ and
	// carry the original content; parent dirs must be present.
	tr := tar.NewReader(buf)
	gotFiles := map[string]string{}
	gotDirs := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			gotDirs[strings.TrimSuffix(hdr.Name, "/")] = true
			if hdr.Mode != 0o755 {
				t.Errorf("dir %s mode = %o, want 755", hdr.Name, hdr.Mode)
			}
		case tar.TypeReg:
			content, _ := io.ReadAll(tr)
			gotFiles[hdr.Name] = string(content)
			if hdr.Mode != 0o644 {
				t.Errorf("file %s mode = %o, want 644", hdr.Name, hdr.Mode)
			}
			if !strings.HasPrefix(hdr.Name, "skill/") {
				t.Errorf("file %s escapes skill/ root", hdr.Name)
			}
		}
	}

	if gotFiles["skill/run.py"] != "print('hello')" {
		t.Errorf("run.py content mismatch: %q", gotFiles["skill/run.py"])
	}
	if gotFiles["skill/lib/helpers.py"] != "def f(): pass" {
		t.Errorf("lib/helpers.py content mismatch")
	}
	if len(gotFiles) != 3 {
		t.Errorf("expected 3 files, got %d", len(gotFiles))
	}
	if !gotDirs["skill"] || !gotDirs["skill/lib"] {
		t.Errorf("missing dir entries: %v", gotDirs)
	}
}

func TestBuildSkillFilesArchiveRejectsTraversal(t *testing.T) {
	if _, err := buildSkillFilesArchive(map[string]string{"../evil": b64("x")}); err == nil {
		t.Error("expected traversal rejection at archive build")
	}
}

// ── Skill-run admission (bind sources, network mode, image) ─────────────────

// skillRootFixture builds a plausible controller layout under a temp dir:
// a skills tree with one skill in it, a data root, and a secrets file
// OUTSIDE both — the thing the finding actually reads.
func skillRootFixture(t *testing.T) (skillsRoot, skillDir, dataRoot, outside string) {
	t.Helper()
	base := t.TempDir()
	skillsRoot = filepath.Join(base, "repo", "skills")
	skillDir = filepath.Join(skillsRoot, "hello")
	dataRoot = filepath.Join(base, "data")
	outside = filepath.Join(base, "etc")
	for _, d := range []string{skillDir, dataRoot, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "noo-node-agent.env"),
		[]byte("NOO_CLUSTER_SECRET=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOO_SKILLS_HOST_DIR", skillsRoot)
	t.Setenv("NOO_DATA_ROOT", dataRoot)
	t.Setenv("NOO_SKILL_BIND_ROOTS", "")
	return
}

// The legitimate legacy shape — the skills dir at /skill — must keep working:
// the fix constrains the bind source, it does not delete the transport.
func TestValidateSkillVolumesAllowsSkillsDir(t *testing.T) {
	_, skillDir, dataRoot, _ := skillRootFixture(t)
	if err := validateSkillVolumes(map[string]string{skillDir: "/skill"}); err != nil {
		t.Fatalf("legitimate skills-dir mount rejected: %v", err)
	}
	if err := validateSkillVolumes(map[string]string{dataRoot: "/data"}); err != nil {
		t.Fatalf("data-root mount rejected: %v", err)
	}
}

// The finding, as a test: `{"volumes":{"/":"/h"}}` plus a `cat` command was
// one request to read this node's cluster secret, NATS credential, agent
// token and private node key, because the container's stdout comes back in
// the response.
func TestValidateSkillVolumesRefusesOutsideRoots(t *testing.T) {
	_, _, _, outside := skillRootFixture(t)
	for _, src := range []string{"/", "/etc", "/root", outside} {
		err := validateSkillVolumes(map[string]string{src: "/h"})
		if err == nil {
			t.Errorf("bind source %q must be refused", src)
			continue
		}
		if !strings.Contains(err.Error(), src) {
			t.Errorf("error for %q must name the offending path, got: %v", src, err)
		}
	}
}

// A prefix test on the raw string is defeated by traversal; canonicalization
// happens before the containment check, so it is not.
func TestValidateSkillVolumesRefusesTraversal(t *testing.T) {
	skillsRoot, _, _, _ := skillRootFixture(t)
	for _, src := range []string{
		skillsRoot + "/../../etc",
		skillsRoot + "/hello/../../..",
		filepath.Dir(skillsRoot) + "/skills/../../etc",
	} {
		if err := validateSkillVolumes(map[string]string{src: "/h"}); err == nil {
			t.Errorf("traversal source %q must be refused", src)
		}
	}
}

// A symlink planted inside an allowed root must not become a tunnel out of it.
func TestValidateSkillVolumesRefusesSymlinkEscape(t *testing.T) {
	skillsRoot, _, _, outside := skillRootFixture(t)
	link := filepath.Join(skillsRoot, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := validateSkillVolumes(map[string]string{link: "/h"}); err == nil {
		t.Fatal("a symlink out of the skills root must be refused")
	}
}

// A sibling directory whose name merely starts with the root's is not inside
// it — the boundary is a path separator.
func TestValidateSkillVolumesRootPrefixIsNotContainment(t *testing.T) {
	skillsRoot, _, _, _ := skillRootFixture(t)
	sibling := skillsRoot + "-evil"
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateSkillVolumes(map[string]string{sibling: "/h"}); err == nil {
		t.Fatalf("%q must not count as inside %q", sibling, skillsRoot)
	}
}

// No configured root means no bind mount at all — refused with a message that
// tells the operator which knob to set, rather than dropped in silence.
func TestValidateSkillVolumesNoRootsConfigured(t *testing.T) {
	_, skillDir, _, _ := skillRootFixture(t)
	t.Setenv("NOO_SKILLS_HOST_DIR", "")
	t.Setenv("NOO_DATA_ROOT", "")
	err := validateSkillVolumes(map[string]string{skillDir: "/skill"})
	if err == nil {
		t.Fatal("no roots configured must refuse every bind mount")
	}
	if !strings.Contains(err.Error(), "NOO_SKILLS_HOST_DIR") {
		t.Fatalf("error should name the knob, got: %v", err)
	}
}

// "/" as a configured root would give the whole hole back through config;
// unusable roots are dropped, and dropping them all means no binds.
func TestSkillBindRootsRejectsUnusableRoots(t *testing.T) {
	t.Setenv("NOO_SKILLS_HOST_DIR", "/")
	t.Setenv("NOO_DATA_ROOT", "/etc")
	t.Setenv("NOO_SKILL_BIND_ROOTS", "relative/path")
	if roots := skillBindRoots(); len(roots) != 0 {
		t.Fatalf("expected no usable roots, got %v", roots)
	}
}

// network_mode "host" puts the sandbox on this node's loopback, in reach of
// the agent's own API and every other service that trusts 127.0.0.1.
func TestValidateSkillRunRequestRefusesHostNetwork(t *testing.T) {
	skillRootFixture(t)
	for _, nm := range []string{"host", "HOST", " host "} {
		req := &SkillRunRequest{Image: "busybox", ContainerName: "noo-skill-1", NetworkMode: nm}
		if err := ValidateSkillRunRequest(req); err == nil {
			t.Errorf("network_mode %q must be refused", nm)
		}
	}
	ok := &SkillRunRequest{Image: "busybox", ContainerName: "noo-skill-1", NetworkMode: "none"}
	if err := ValidateSkillRunRequest(ok); err != nil {
		t.Fatalf("network_mode none rejected: %v", err)
	}
}

func TestValidateSkillImage(t *testing.T) {
	bad := []string{"", "   ", "busybox ", " busybox", "busy;box", "busybox`id`",
		"busybox$(id)", "-rm", "busybox\n", "img|other"}
	for _, img := range bad {
		if err := validateSkillImage(img); err == nil {
			t.Errorf("image %q must be refused", img)
		}
	}
	good := []string{"busybox", "busybox:1.36", "noo-sandbox-base:latest",
		"ghcr.io/noomesh/noo-sandbox-base:latest",
		"registry.local:5000/team/img@sha256:" + strings.Repeat("a", 64)}
	for _, img := range good {
		if err := validateSkillImage(img); err != nil {
			t.Errorf("image %q should be accepted: %v", img, err)
		}
	}
}

// Inline files win over volumes, so a request that ships files is not held to
// the bind rules — but its files are still validated.
func TestValidateSkillRunRequestFilesBypassVolumeCheck(t *testing.T) {
	skillRootFixture(t)
	req := &SkillRunRequest{
		Image:         "busybox",
		ContainerName: "noo-skill-1",
		Volumes:       map[string]string{"/": "/h"},
		Files:         map[string]string{"run.py": b64("print(1)")},
	}
	if err := ValidateSkillRunRequest(req); err != nil {
		t.Fatalf("inline-files request rejected: %v", err)
	}
	req.Files = map[string]string{"../evil.py": b64("x")}
	if err := ValidateSkillRunRequest(req); err == nil {
		t.Fatal("traversal in inline files must still be refused")
	}
}
