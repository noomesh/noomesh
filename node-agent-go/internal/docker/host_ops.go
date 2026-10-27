// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Host filesystem operations via short-lived helper containers.
//
// The node-agent container doesn't mount arbitrary host paths, but it
// drives Docker — and Docker is root on the host. Anything an operator
// would SSH in for (create a data dir, fix ownership, check a model file)
// runs here through a disposable container instead. This is the
// "no manual configuration on remote devices" principle from
// DESIRED_STATE_CONFIG.md: if a fix needs SSH, that's a design gap.
package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// helperImage returns the image host operations run in: the agent's own
// (alpine-based, has sh/chown/test, and carries the agent binary that
// `-preseed` needs).
//
// It used to say "guaranteed to exist on the node". It is not, and was not:
// a host-process node installs a BINARY and never asks Docker for the image
// whose name that binary derives. EnsureHelperImage makes the guarantee
// real by fetching it over the artifact rail; this function only names it.
//
// NOO_HELPER_IMAGE pins it;
// otherwise it is derived from the release pair the agent env carries
// (NOO_IMAGE_PREFIX/NOO_IMAGE_TAG — the exact image the stack pulled), and
// only then the namespace default. The old literal named the pre-rename
// local build ("pai-assistant/node-agent:latest"), which no released node
// has: every models-dir ensure on the controller's self-agent failed with
// "No such image".
func helperImage() string {
	if img := os.Getenv("NOO_HELPER_IMAGE"); img != "" {
		return img
	}
	prefix := strings.TrimRight(os.Getenv("NOO_IMAGE_PREFIX"), "/")
	tag := os.Getenv("NOO_IMAGE_TAG")
	if prefix == "" {
		prefix = DefaultImagePrefix
	}
	if tag == "" {
		tag = "latest"
	}
	return prefix + "/node-agent:" + tag
}

// runHelper runs cmd in a disposable container with the given binds, waiting up
// to timeout for it to exit. Returns exit code and combined output (truncated).
// Quick host ops pass a short timeout; bulk jobs (e.g. model-weight preseed,
// which copies multi-GB weights) pass a long one — a fixed 60s silently killed
// preseed mid-copy.
func (c *Client) runHelper(ctx context.Context, binds []string, cmd []string, timeout time.Duration) (int, string, error) {
	return c.runHelperScript(ctx, binds, strings.Join(cmd, " "), nil, timeout)
}

// runHelperScript runs a shell SCRIPT with positional ARGUMENTS, so a value
// that came from outside this process is never spliced into the command
// line as text.
//
// The difference is the whole point. `sh -c "mkdir -p /hostparent/$LEAF"`
// re-parses $LEAF as shell source: a space forks two paths, a `;` forks a
// second command. `sh -c 'mkdir -p "/hostparent/$1"' sh "$LEAF"` hands the
// same bytes to the shell as one already-split word, whatever is in them.
// Callers still validate their inputs (hostPathLeafOK); this is the layer
// that makes a missed validation a wrong path instead of an extra command.
func (c *Client) runHelperScript(ctx context.Context, binds []string, script string, args []string, timeout time.Duration) (int, string, error) {
	// The image first. A host-process node never pulled it and cannot reach
	// the private registry, so "No such image" from ContainerCreate was the
	// normal state of a fresh node — and callers read that generic error as
	// their own kind of miss. Fetch it over the artifact rail, or fail with
	// a typed error the caller can tell apart. See helper_image.go.
	if err := c.EnsureHelperImage(ctx); err != nil {
		return -1, "", err
	}
	// Docker appends Cmd to Entrypoint, so the argv is:
	//   /bin/sh -c <script> sh <args…>
	// The literal "sh" is $0; the caller's args start at $1.
	cmdv := []string{script}
	if len(args) > 0 {
		cmdv = append(cmdv, "sh")
		cmdv = append(cmdv, args...)
	}
	cfg := &container.Config{
		Image:      helperImage(),
		Entrypoint: []string{"/bin/sh", "-c"},
		Cmd:        cmdv,
		Labels:     map[string]string{"noo.managed-by": "node-agent-go", "noo.helper": "true"},
	}
	hostCfg := &container.HostConfig{
		Binds:      binds,
		AutoRemove: false, // remove manually after reading logs
	}

	resp, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     cfg,
		HostConfig: hostCfg,
	})
	if err != nil {
		return -1, "", fmt.Errorf("helper create: %w", err)
	}
	// Removal must outlive a cancelled ctx, or a cancelled op leaks the helper.
	defer c.docker.ContainerRemove(context.WithoutCancel(ctx), resp.ID,
		client.ContainerRemoveOptions{Force: true})

	if _, err := c.docker.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return -1, "", fmt.Errorf("helper start: %w", err)
	}

	waitRes := c.docker.ContainerWait(ctx, resp.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	waitCh, errCh := waitRes.Result, waitRes.Error
	var exit int
	select {
	case w := <-waitCh:
		exit = int(w.StatusCode)
	case err := <-errCh:
		return -1, "", fmt.Errorf("helper wait: %w", err)
	case <-time.After(timeout):
		return -1, "", fmt.Errorf("helper timed out after %s", timeout)
	}

	out := ""
	if logs, err := c.docker.ContainerLogs(ctx, resp.ID,
		client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}); err == nil {
		var buf bytes.Buffer
		io.CopyN(&buf, logs, 2048) //nolint:errcheck
		logs.Close()
		out = buf.String()
	}
	return exit, out, nil
}

// forbiddenDirPrefixes bounds what desired-state data can make the helper
// touch. The agent's docker.sock is root-equivalent by design (it starts
// backend containers), but the DESIRED CONFIG comes from the controller's
// DB — a compromised gateway/DB row must not translate into `chown /etc`
// or `/root/.ssh` on every node. This list is compiled into the agent
// (NOT DB-driven) — the same trust split as the executor's file-based
// SSH allowlist: data plane proposes, local binary constrains.
var forbiddenDirPrefixes = []string{
	"/etc", "/root", "/usr", "/bin", "/sbin", "/lib", "/boot", "/proc",
	"/sys", "/dev", "/run", "/var/run", "/var/lib/docker",
}

// hostDirAllowed rejects system paths and anything not clearly a data dir.
func hostDirAllowed(dir string) error {
	clean := strings.TrimSuffix(dir, "/")
	if clean == "" || !strings.HasPrefix(clean, "/") || strings.Contains(clean, "..") {
		return fmt.Errorf("invalid dir %q", dir)
	}
	for _, p := range forbiddenDirPrefixes {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return fmt.Errorf("refusing system path %q (forbidden prefix %s)", dir, p)
		}
	}
	// ~/.ssh and friends: never manage dotfile paths.
	if strings.Contains(clean, "/.") {
		return fmt.Errorf("refusing hidden path %q", dir)
	}
	return nil
}

// EnsureHostDir creates dir on the HOST (mkdir -p) and chowns it to owner
// (a username resolved against the host's /etc/passwd, or uid[:gid]).
// Idempotent. Root-owned parents are fine — the helper runs as root.
// Guarded by hostDirAllowed: desired-state data cannot direct the helper
// at system paths.
func (c *Client) EnsureHostDir(ctx context.Context, dir, owner string) error {
	if dir == "" || !strings.HasPrefix(dir, "/") {
		return fmt.Errorf("EnsureHostDir: invalid dir %q", dir)
	}
	// The controller PROPOSES this path; the node DISPOSES. hostDirAllowed
	// is a denylist and always was — it stops /etc and /root, not
	// /home/someone or /mnt/anything. ValidateHostPathUnderRoots is the
	// allowlist: the path must resolve under a root this node declared in
	// its own environment.
	clean, err := ValidateHostPathUnderRoots(dir)
	if err != nil {
		return fmt.Errorf("EnsureHostDir: %w", err)
	}
	dir = clean
	// Owner must be a plain username or uid[:gid] — no shell metacharacters
	// (it's interpolated into the helper's sh -c command line).
	for _, r := range owner {
		if !(r == ':' || r == '.' || r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("EnsureHostDir: invalid owner %q", owner)
		}
	}
	if owner == "" {
		owner = "1000:1000"
	}
	// Mount the parent so mkdir happens ON the host fs; mount passwd/group
	// read-only so chown can resolve names.
	parent := dir[:strings.LastIndex(dir, "/")]
	if parent == "" {
		parent = "/"
	}
	leaf := dir[strings.LastIndex(dir, "/")+1:]
	// The leaf used to be interpolated into `sh -c` unquoted. hostDirAllowed
	// rejects ".." and system prefixes; it does not reject a space or a ';',
	// so a models_dir ending in `x; wget …|sh` ran as root in a container
	// with the parent directory bind-mounted read-write.
	if err := hostPathLeafOK(leaf); err != nil {
		return fmt.Errorf("EnsureHostDir: %w", err)
	}
	// Done IN PROCESS. This used to run `mkdir -p && chown` inside a helper
	// container with the parent bind-mounted, which made sense when the agent
	// itself ran in a container and could not touch the host filesystem. It has
	// been a host process since the fleet hardening, so the container bought
	// nothing and cost a dependency: the node needed the agent IMAGE, which no
	// rail delivers to a host-process node.
	//
	// The cost was not theoretical. Moving a node's data root to a path that
	// the node had just accepted then failed with `helper_image_missing`, whose
	// remedy names `noo cluster sync-images` — and sync-images declines
	// node-agent refs, saying that is `upgrade-agents`' job, which needs a
	// checkout the node does not have. A refusal loop with no way out, on a
	// node that only needed a directory created. Same
	// lesson as the weight preseeds, which moved in-process for this reason.
	//
	// Every check above still runs first: the path must resolve under a root
	// this node declared, and the leaf must be a plain name. Those are the
	// security boundary; the container never was.
	_ = parent
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// A `mkdir X: permission denied` on a path whose parents exist is
		// almost never about X. On host8 (2026-09-13 → 09-18) the data
		// root lived under /media/<user>/, a udisks mount parent that is
		// 750 root:root plus an ACL for that one user: the agent's own
		// system user could not traverse it, saw the drive as absent, tried
		// to create the mount point and was refused — five days of
		// `models_dir_refused` naming the wrong directory. Name the
		// ancestor instead; the applier grants traverse on it.
		if anc := untraversableAncestor(dir); anc != "" {
			return fmt.Errorf("EnsureHostDir %s: %s is not traversable by this agent (uid %d) — "+
				"every ancestor needs execute permission for the agent's user; "+
				"the applier grants it on the next `noo cluster provision`, or run "+
				"`setfacl -m u:$(id -un):--x %s` as root (mkdir: %v)", dir, anc, os.Getuid(), anc, err)
		}
		return fmt.Errorf("EnsureHostDir %s: %w", dir, err)
	}
	uid, gid, err := resolveOwner(owner)
	if err != nil {
		return fmt.Errorf("EnsureHostDir %s: %w", dir, err)
	}
	chownHostDir(dir, owner, uid, gid)
	slog.Info("host dir ensured", "dir", dir, "owner", owner)
	return nil
}

// chownWarned remembers the (dir, owner) pairs whose "cannot chown" warning has
// been logged. EnsureHostDir runs every reconcile tick (5 min), the agent is
// unprivileged, and on WSL2 the data root is owned by another uid, so the same
// chown failed and logged forever (awolf, 2026-10) and drowned real faults.
var chownWarned sync.Map

// chownHostDir makes dir owned by uid:gid when it is not already, and never
// fails the reconcile: a directory with the wrong owner is still usable by a
// backend running as that owner. Ownership is checked FIRST, so a directory that
// is already right costs nothing and never warns; a chown that is not permitted
// warns exactly once per (dir, owner) for the life of the process, with the fix.
func chownHostDir(dir, owner string, uid, gid int) {
	if st, err := os.Stat(dir); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) == uid && int(sys.Gid) == gid {
			return
		}
	}
	err := os.Chown(dir, uid, gid)
	if err == nil {
		return
	}
	key := dir + "\x00" + owner
	if _, seen := chownWarned.LoadOrStore(key, true); seen {
		return
	}
	slog.Warn("host dir not chowned; this agent cannot change its owner and will not retry",
		"dir", dir, "owner", owner, "error", err,
		"effect", "a backend running as that user may not be able to write here",
		"fix", fmt.Sprintf("run `noo cluster provision` for this node (the applier owns data-root "+
			"ownership), or as root: chown %d:%d %s", uid, gid, dir))
}

// untraversableAncestor walks from dir towards / and returns the first
// EXISTING directory the current process cannot traverse (no execute bit
// for it), or "" when every existing ancestor is traversable — in which
// case a mkdir failure really is about the leaf.
func untraversableAncestor(dir string) string {
	d := dir
	for d != "/" && d != "." && d != "" {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			if syscall.Access(d, 1 /* X_OK */) != nil {
				return d
			}
		}
		d = filepath.Dir(d)
	}
	return ""
}

// resolveOwner turns "name", "uid", "uid:gid" or "name:group" into numeric ids.
//
// The helper container mounted /etc/passwd read-only so `chown` could resolve a
// NAME; in process the same lookup is os/user's job. A name that does not exist
// on this node is an error rather than a silent fallback to root, because
// chowning a model store to root is how a backend running as the operator
// silently loses write access.
func resolveOwner(owner string) (int, int, error) {
	if owner == "" {
		owner = "1000:1000"
	}
	name, group, hasGroup := strings.Cut(owner, ":")
	uid, uerr := strconv.Atoi(name)
	if uerr != nil {
		u, err := user.Lookup(name)
		if err != nil {
			return 0, 0, fmt.Errorf("owner %q: %w", owner, err)
		}
		uid, _ = strconv.Atoi(u.Uid)
		if !hasGroup {
			gid, _ := strconv.Atoi(u.Gid)
			return uid, gid, nil
		}
	}
	if !hasGroup {
		return uid, uid, nil
	}
	gid, gerr := strconv.Atoi(group)
	if gerr != nil {
		g, err := user.LookupGroup(group)
		if err != nil {
			return 0, 0, fmt.Errorf("owner %q: %w", owner, err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return uid, gid, nil
}

// HostFileExists reports whether dir/file exists on the host.
func (c *Client) HostFileExists(ctx context.Context, dir, file string) (bool, error) {
	if dir == "" || file == "" || strings.Contains(file, "/") {
		return false, fmt.Errorf("HostFileExists: invalid args")
	}
	clean, err := ValidateHostPathUnderRoots(dir)
	if err != nil {
		return false, fmt.Errorf("HostFileExists: %w", err)
	}
	if err := hostPathLeafOK(file); err != nil {
		return false, fmt.Errorf("HostFileExists: %w", err)
	}
	binds := []string{clean + ":/hostdir:ro"}
	exit, _, err := c.runHelperScript(ctx, binds, `test -e "/hostdir/$1"`, []string{file}, 60*time.Second)
	if err != nil {
		return false, err
	}
	return exit == 0, nil
}
