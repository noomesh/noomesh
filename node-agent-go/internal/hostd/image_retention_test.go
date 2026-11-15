// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func h64(c string) string { return strings.Repeat(c, 64)[:64] }
func iid(c string) string { return "sha256:" + h64(c) }

const nsNoo = "ghcr.io/noomesh/"
const nsAddon = "ghcr.io/rhowner/"

func writeKeep(t *testing.T, dir string, k keepFile) string {
	t.Helper()
	p := filepath.Join(dir, imageKeepBasename)
	b, _ := json.Marshal(k)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestKeepFileMustBeProvablyCurrentAndMeaningful(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "stack.lock")
	os.WriteFile(lock, []byte("# tag v0.6.24\nghcr.io/noomesh/gateway@sha256:"+h64("a")+"\n"), 0o644)
	good := keepFile{Version: 1, Namespaces: []string{nsNoo},
		Sources: []keepSource{{Path: lock, SHA256: sha([]byte("# tag v0.6.24\nghcr.io/noomesh/gateway@sha256:" + h64("a") + "\n"))}},
		Keep:    []keepEntry{{Ref: "ghcr.io/noomesh/gateway@sha256:" + h64("a"), Why: "stack.lock (v0.6.24)"}}}
	p := writeKeep(t, dir, good)
	if _, err := loadKeepFile(p, time.Now(), os.ReadFile); err != nil {
		t.Fatalf("a current keep file was refused: %v", err)
	}
	// The lock moved on (a roll) and the keep file did not: stale.
	os.WriteFile(lock, []byte("# tag v0.6.25\n"), 0o644)
	if _, err := loadKeepFile(p, time.Now(), os.ReadFile); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("a keep file built from another lock was believed: %v", err)
	}
	cases := map[string]keepFile{
		"no namespace":      {Version: 1, MaxAgeSeconds: 60, WrittenAt: time.Now().UTC().Format(time.RFC3339), Keep: good.Keep},
		"empty keep":        {Version: 1, MaxAgeSeconds: 60, WrittenAt: time.Now().UTC().Format(time.RFC3339), Namespaces: []string{nsNoo}},
		"wrong version":     {Version: 2, MaxAgeSeconds: 60, WrittenAt: time.Now().UTC().Format(time.RFC3339), Namespaces: []string{nsNoo}, Keep: good.Keep},
		"no currency proof": {Version: 1, Namespaces: []string{nsNoo}, Keep: good.Keep},
		"bare-name entry":   {Version: 1, MaxAgeSeconds: 60, WrittenAt: time.Now().UTC().Format(time.RFC3339), Namespaces: []string{nsNoo}, Keep: []keepEntry{{Ref: "ghcr.io/noomesh/gateway:v0.6.24"}}},
		"namespace no host": {Version: 1, MaxAgeSeconds: 60, WrittenAt: time.Now().UTC().Format(time.RFC3339), Namespaces: []string{"noomesh/"}, Keep: good.Keep},
		"stale by age":      {Version: 1, MaxAgeSeconds: 60, WrittenAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), Namespaces: []string{nsNoo}, Keep: good.Keep},
	}
	for name, k := range cases {
		p := writeKeep(t, t.TempDir(), k)
		if _, err := loadKeepFile(p, time.Now(), os.ReadFile); err == nil {
			t.Errorf("%s: believed", name)
		}
	}
	if _, err := loadKeepFile("image-keep.json", time.Now(), os.ReadFile); err == nil {
		t.Error("a relative keep path was accepted")
	}
	if _, err := loadKeepFile(filepath.Join(dir, "other.json"), time.Now(), os.ReadFile); err == nil {
		t.Error("a keep file not named image-keep.json was accepted")
	}
}

func TestClassifyKeepsWhatIsUsedForeignOrKeptAndRemovesOnlyOursSuperseded(t *testing.T) {
	k := &keepFile{Namespaces: []string{nsNoo, nsAddon}, Keep: []keepEntry{
		{Ref: nsNoo + "gateway@sha256:" + h64("1"), Why: "stack.lock (v0.6.24)"},
		{Ref: nsNoo + "gateway@sha256:" + h64("2"), Why: "stack.lock.prev (v0.6.23)"},
		{Ref: nsAddon + "rhaddon@sha256:" + h64("3"), Why: "addons.lock rhaddon (current)"},
		{ID: iid("4"), Why: "node: rail manifest vouches for it"},
		{Ref: nsAddon + "rhaddon@sha256:" + h64("5"), Why: "last pin of disabled add-on rhaddon"},
	}}
	imgs := []imageFacts{
		{ID: iid("a"), Digests: []string{nsNoo + "gateway@sha256:" + h64("1")}, Bytes: 10},            // current
		{ID: iid("b"), Digests: []string{nsNoo + "gateway@sha256:" + h64("2")}, Bytes: 11},            // previous
		{ID: iid("c"), Digests: []string{nsNoo + "gateway@sha256:" + h64("9")}, Bytes: 2_457_000_000}, // superseded, untagged
		{ID: iid("d"), Tags: []string{nsNoo + "ollama:v0.6.22"}, Bytes: 8_016_000_000},                // used by 2 stopped containers
		{ID: iid("e"), Tags: []string{"ollama/ollama:latest"}, Bytes: 9_257_000_000},                  // the operator's own
		{ID: iid("f"), Bytes: 5},             // dangling
		{ID: iid("4"), Bytes: 1_800_000_000}, // rail-loaded, vouched by id
		{ID: iid("g"), Tags: []string{nsAddon + "rhaddon:stack0611-worker"}, Bytes: 8_967_000_000}, // retired tag, superseded
		{ID: iid("h"), Digests: []string{nsAddon + "rhaddon@sha256:" + h64("3")}, Bytes: 8_967_000_000},
		{ID: iid("i"), Tags: []string{nsNoo + "x:1", "docker.io/library/x:1"}, Bytes: 7},    // one foreign name keeps it
		{ID: iid("j"), Digests: []string{nsAddon + "rhaddon@sha256:" + h64("5")}, Bytes: 6}, // disabled add-on's last pin
	}
	used := map[string]bool{iid("d"): true}
	got := map[string]imageVerdict{}
	for _, v := range classifyImages(imgs, used, k) {
		got[v.ID] = v
	}
	want := map[string]string{
		iid("a"): "kept: stack.lock (v0.6.24)",
		iid("b"): "kept: stack.lock.prev (v0.6.23)",
		iid("c"): "remove:",
		iid("d"): "kept: used by a container",
		iid("e"): "kept: not ours (ollama/ollama:latest)",
		iid("f"): "skipped: no tag and no digest",
		iid("4"): "kept: node: rail manifest vouches for it",
		iid("g"): "remove:",
		iid("h"): "kept: addons.lock rhaddon (current)",
		iid("i"): "kept: not ours (docker.io/library/x:1)",
		iid("j"): "kept: last pin of disabled add-on rhaddon",
	}
	for id, prefix := range want {
		v := got[id]
		if !strings.HasPrefix(v.Why, prefix) {
			t.Errorf("%s: %q, want %q", id[:14], v.Why, prefix)
		}
		if v.Remove != strings.HasPrefix(prefix, "remove") {
			t.Errorf("%s: remove=%v", id[:14], v.Remove)
		}
	}
}

func TestRefRepoAndNamespaceAreExact(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/noomesh/gateway:v0.6.24":            "ghcr.io/noomesh/gateway",
		"ghcr.io/noomesh/gateway@sha256:" + h64("a"): "ghcr.io/noomesh/gateway",
		"localhost:5000/rh/rhaddon:0.1.0":            "localhost:5000/rh/rhaddon",
		"localhost:5000/rh/rhaddon":                  "localhost:5000/rh/rhaddon",
	} {
		if got := refRepo(in); got != want {
			t.Errorf("refRepo(%q) = %q, want %q", in, got, want)
		}
	}
	// A look-alike registry path is not ours.
	if underNamespace("ghcr.io/noomesh-evil/gateway:1", []string{nsNoo}) {
		t.Error("ghcr.io/noomesh-evil/ was taken for ghcr.io/noomesh/")
	}
}

func TestParseHumanBytes(t *testing.T) {
	for in, want := range map[string]int64{"2.457GB": 2_457_000_000, "91.42MB": 91_420_000, "30.67kB": 30_670, "2B": 2} {
		if got, ok := parseHumanBytes(in); !ok || got != want {
			t.Errorf("%s -> %d %v", in, got, ok)
		}
	}
	if _, ok := parseHumanBytes("lots"); ok {
		t.Error("junk parsed")
	}
}

// The post-roll op: rung 5 alone. Live, it removes only the superseded image
// of ours, by ref and then by ID, never with -f, and writes the report.
func TestPostRollRemovesOnlyOursSupersededNeverForced(t *testing.T) {
	e, fr := testEngine(t)
	dir := t.TempDir()
	keep := writeKeep(t, dir, keepFile{Version: 1, MaxAgeSeconds: 3600, WrittenAt: time.Now().UTC().Format(time.RFC3339),
		Namespaces: []string{nsNoo},
		Keep:       []keepEntry{{Ref: nsNoo + "gateway@sha256:" + h64("1"), Why: "stack.lock (v0.6.24)"}}})
	fr.stdout = map[string]string{
		"ps -aq --no-trunc":           "c1\n",
		"inspect --format {{.Image}}": iid("d") + "\n",
		"image ls -aq --no-trunc":     iid("a") + "\n" + iid("c") + "\n" + iid("d") + "\n" + iid("e") + "\n",
		"--format {{.Id}}|{{json":     iid("a") + `|[]|["` + nsNoo + "gateway@sha256:" + h64("1") + `"]|10` + "\n" + iid("c") + `|[]|["` + nsNoo + "gateway@sha256:" + h64("9") + `"]|2457000000` + "\n" + iid("d") + `|["` + nsNoo + `ollama:v0.6.22"]|[]|8000000000` + "\n" + iid("e") + `|["ollama/ollama:latest"]|null|9000000000` + "\n",
		"system df -v":                "{}",
	}
	fr.rc = map[string]int{"image inspect --format {{.Id}} sha256": 1} // gone after its refs were removed
	r := queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "only=superseded-images", "keep=" + keep}})
	if r.RC != 0 {
		t.Fatalf("post-roll rung failed: %+v", r)
	}
	var rms []string
	for _, c := range fr.joined() {
		if strings.Contains(c, "image rm") {
			rms = append(rms, c)
			if strings.Contains(c, " -f") || strings.Contains(c, "--force") {
				t.Errorf("forced: %s", c)
			}
		}
		if strings.Contains(c, "prune") {
			t.Errorf("the post-roll step ran another rung: %s", c)
		}
	}
	if len(rms) != 1 || !strings.Contains(rms[0], "gateway@sha256:"+h64("9")) {
		t.Fatalf("removed %v, want only the superseded gateway digest", rms)
	}
	if !strings.Contains(r.Stderr, "removed 1") {
		t.Errorf("report: %+v", r)
	}
	b, err := os.ReadFile(filepath.Join(dir, imageReportBasename))
	if err != nil || !strings.Contains(string(b), `"result": "removed"`) || !strings.Contains(string(b), "not ours (ollama/ollama:latest)") {
		t.Errorf("report file: %v\n%s", err, b)
	}
}

func TestNoKeepFileRemovesNothingAndSaysWhy(t *testing.T) {
	e, fr := testEngine(t)
	r := queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=false", "only=superseded-images", "keep=" + filepath.Join(t.TempDir(), imageKeepBasename)}})
	for _, c := range fr.joined() {
		if strings.Contains(c, "image rm") || strings.Contains(c, "image ls") {
			t.Errorf("acted without a keep file: %s", c)
		}
	}
	if !strings.Contains(r.Stderr, "SKIPPED") {
		t.Errorf("did not say it skipped: %+v", r)
	}
	r = queue(t, e, "d", Command{Op: "disk-reclaim", Service: "docker", Args: []string{"dry_run=false", "only=superseded-images"}})
	if r.RC == 0 {
		t.Errorf("only=superseded-images without keep= succeeded: %+v", r)
	}
}

func TestKeepSpoolTokenResolvesToThisHostdsSpool(t *testing.T) {
	if got := resolveKeepArg("spool", "/srv/noo/.noo-host-spool"); got != "/srv/noo/.noo-host-spool/image-keep.json" {
		t.Fatalf("keep=spool must name the keep file in this hostd's spool, got %q", got)
	}
	if got := resolveKeepArg("/x/image-keep.json", "/srv/noo/.noo-host-spool"); got != "/x/image-keep.json" {
		t.Fatalf("an explicit path must pass through, got %q", got)
	}
	got := resolveKeepArg("spool", "")
	if _, err := loadKeepFile(got, time.Now(), func(string) ([]byte, error) { return []byte("{}"), nil }); err == nil {
		t.Fatalf("with no spool known the token must be refused, not read (%q)", got)
	}
}

// Real `docker image inspect --format imageInspectFormat` output, captured
// 2026-11-14 in docker:27-dind (27.5.1, overlay2), docker:28-dind (28.5.2,
// overlay2) and docker:29-dind (29.9.3, containerd image store) after pulling
// two of 0.6.25-rc.1's lock rows by digest (a Docker Hub short name and a
// ghcr.io/noomesh/dhi base image) and importing one tagged image. The old
// `{{join .RepoTags ","}}` template failed on 27 and 28 for every image:
// "template parsing error: template: :1:15: executing "" at <.RepoTags>:
// wrong type for value; expected []string; got []interface {}".
var capturedInspect = map[string]string{
	"27.5.1": `sha256:073ccfa5190b3b463a3fcf96e85c57584707cb0e37e977effc0b13df38ad27da|[]|["nats@sha256:67ac7866d010e8d83302dd30332eeae1a2b7a8ee051155e2eb5a5485b720cd4b"]|18008350
sha256:eaf6a5a4da7b0a6000794c47f629250c98b217310d1a88f7611154ae88ac7f89|[]|["ghcr.io/noomesh/dhi/alertmanager@sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda"]|59260398
sha256:fbe74339aedd622fd4d3d9f212343a34ff656273a685690c87c2315f78d3b655|["ghcr.io/noomesh/rh-retention:old"]|[]|0`,
	"28.5.2": `sha256:0429c14ac32cb2d97c735e4b07479990ba1eb4d93a451566688e0cba66832809|["ghcr.io/noomesh/rh-retention:old"]|[]|0
sha256:073ccfa5190b3b463a3fcf96e85c57584707cb0e37e977effc0b13df38ad27da|[]|["nats@sha256:67ac7866d010e8d83302dd30332eeae1a2b7a8ee051155e2eb5a5485b720cd4b"]|18008350
sha256:eaf6a5a4da7b0a6000794c47f629250c98b217310d1a88f7611154ae88ac7f89|[]|["ghcr.io/noomesh/dhi/alertmanager@sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda"]|59260398`,
	"29.9.3": `sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda|["ghcr.io/noomesh/dhi/alertmanager@sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda"]|["ghcr.io/noomesh/dhi/alertmanager@sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda"]|80869556
sha256:67ac7866d010e8d83302dd30332eeae1a2b7a8ee051155e2eb5a5485b720cd4b|["nats@sha256:67ac7866d010e8d83302dd30332eeae1a2b7a8ee051155e2eb5a5485b720cd4b"]|["nats@sha256:67ac7866d010e8d83302dd30332eeae1a2b7a8ee051155e2eb5a5485b720cd4b"]|24882667
sha256:bd9daa11cbcd38dd4d34aefc0c48beb93ead1326e27fcbf5800d9a0a62466ca9|["ghcr.io/noomesh/rh-retention:old"]|["ghcr.io/noomesh/rh-retention@sha256:bd9daa11cbcd38dd4d34aefc0c48beb93ead1326e27fcbf5800d9a0a62466ca9"]|4797`,
}

func TestImageListingReadsDocker27To29(t *testing.T) {
	for ver, out := range capturedInspect {
		e, fr := testEngine(t)
		var ids []string
		for _, l := range strings.Split(out, "\n") {
			ids = append(ids, strings.SplitN(l, "|", 2)[0])
		}
		fr.stdout = map[string]string{
			"image ls -aq --no-trunc": strings.Join(ids, "\n") + "\n",
			"--format {{.Id}}|{{json": out + "\n",
			"system df -v":            "{}",
		}
		imgs, err := e.listImages(context.Background())
		if err != nil || len(imgs) != 3 {
			t.Fatalf("%s: %v %d images", ver, err, len(imgs))
		}
		var nats, am, old *imageFacts
		for i := range imgs {
			all := strings.Join(append(append([]string{}, imgs[i].Tags...), imgs[i].Digests...), ",")
			switch {
			case strings.Contains(all, "nats@sha256:67ac78"):
				nats = &imgs[i]
			case strings.Contains(all, "dhi/alertmanager@sha256:01dd89"):
				am = &imgs[i]
			case strings.Contains(all, "rh-retention:old"):
				old = &imgs[i]
			}
		}
		if nats == nil || am == nil || old == nil {
			t.Fatalf("%s: an image's refs were lost: %+v", ver, imgs)
		}
		if old.Bytes != map[string]int64{"27.5.1": 0, "28.5.2": 0, "29.9.3": 4797}[ver] || am.Bytes == 0 {
			t.Errorf("%s: sizes %d %d", ver, old.Bytes, am.Bytes)
		}
		if len(am.Digests) != 1 || am.Digests[0] != "ghcr.io/noomesh/dhi/alertmanager@sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda" {
			t.Errorf("%s: digests %v", ver, am.Digests)
		}
	}
	// `null` (no list at all) is an empty list, not a parse failure.
	if im, ok := parseImageLine(iid("e") + `|["ollama/ollama:latest"]|null|1`); !ok || len(im.Tags) != 1 || len(im.Digests) != 0 {
		t.Errorf("null digests: %+v %v", im, ok)
	}
	// A line that is not the format is no image, never a guess.
	for _, l := range []string{iid("e") + "|ollama/ollama:latest||1", "garbage", iid("e") + "|[]|[]"} {
		if _, ok := parseImageLine(l); ok {
			t.Errorf("parsed %q", l)
		}
	}
}

// A failed inspect skips the rung naming Docker's own error.
func TestImageInspectFailureNamesDockersError(t *testing.T) {
	e, fr := testEngine(t)
	dir := t.TempDir()
	keep := writeKeep(t, dir, keepFile{Version: 1, MaxAgeSeconds: 3600, WrittenAt: time.Now().UTC().Format(time.RFC3339),
		Namespaces: []string{nsNoo}, Keep: []keepEntry{{Ref: nsNoo + "gateway@sha256:" + h64("1")}}})
	fr.stdout = map[string]string{"ps -aq --no-trunc": "", "image ls -aq --no-trunc": iid("a") + "\n"}
	fr.rc = map[string]int{"--format {{.Id}}|{{json": 1}
	r := queue(t, e, "c", Command{Op: "disk-reclaim", Service: "docker",
		Args: []string{"dry_run=true", "only=superseded-images", "keep=" + keep}})
	if !strings.Contains(r.Stderr, "SKIPPED — docker image inspect failed: boom: --format {{.Id}}|{{json") {
		t.Errorf("the skip does not name Docker's error: %+v", r)
	}
}

// The CLI's keep file for the REAL 0.6.25-rc.1 lock with the REAL 0.6.24
// lock as stack.lock.prev, over a real image store (noo-cli
// image_retention.rs the_keep_file_from_the_real_locks_keeps_every_image_either_lock_names
// asserts it builds exactly this golden). Classified against that store
// with NO container using anything (the worst case: a stopped stack), every
// image holding a digest either lock names stays, and an unused image of
// ours in neither lock (a real capture of an imported tagged image) goes,
// so the test is not vacuous.
func TestTheRealKeepFileProtectsBothLocks(t *testing.T) {
	fx := filepath.Join("..", "..", "..", "tests", "fixtures", "image-retention")
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(fx, n))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	var k keepFile
	if err := json.Unmarshal([]byte(read("keep-classic.golden.json")), &k); err != nil {
		t.Fatal(err)
	}
	var imgs []imageFacts
	store := read("classic-overlay2-27.5.1.images") + "\n" + strings.SplitN(strings.Split(read("docker27.images"), "\n")[2], "|", 4)[0] + `|["ghcr.io/noomesh/rh-retention:old"]|[]`
	for _, l := range strings.Split(store, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		im, ok := parseImageLine(l + "|0") // the store capture has no size field
		if !ok {
			t.Fatalf("fixture line did not parse: %s", l)
		}
		imgs = append(imgs, im)
	}
	lockDigests := map[string]bool{}
	for _, n := range []string{"stack-v0.6.25-rc.1.lock", "stack-v0.6.24.lock"} {
		for _, l := range strings.Split(read(n), "\n") {
			if i := strings.Index(l, "@sha256:"); i > 0 && !strings.HasPrefix(l, "#") {
				lockDigests[l[i+8:]] = true
			}
		}
	}
	removed := 0
	for _, v := range classifyImages(imgs, map[string]bool{}, &k) {
		named := false
		for _, r := range v.Refs {
			if i := strings.Index(r, "@sha256:"); i > 0 && lockDigests[r[i+8:]] {
				named = true
			}
		}
		if named && v.Remove {
			t.Errorf("an image a lock names would be removed: %s %v (%s)", v.ID, v.Refs, v.Why)
		}
		if v.Remove {
			removed++
			if len(v.Refs) != 1 || v.Refs[0] != "ghcr.io/noomesh/rh-retention:old" {
				t.Errorf("removed something else: %v", v.Refs)
			}
		}
	}
	if removed != 1 {
		t.Errorf("removed %d, want exactly the unused image in neither lock", removed)
	}
}
