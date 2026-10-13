// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// SkillRunRequest is the payload from the gateway for running a skill container.
type SkillRunRequest struct {
	Image         string            `json:"image"`
	Command       []string          `json:"command"`
	ContainerName string            `json:"container_name"`
	Env           map[string]string `json:"env"`
	MemoryLimit   string            `json:"memory_limit"`
	NetworkMode   string            `json:"network_mode"`
	GPU           bool              `json:"gpu"`
	Timeout       int               `json:"timeout"`
	// Volumes bind-mounts host_path -> container_path read-only. Legacy:
	// the source must exist on THIS node's host filesystem, which is only
	// true on the controller. Ignored when Files is non-empty.
	Volumes map[string]string `json:"volumes"`
	// Files ships the skill directory inline: relative path -> base64
	// content. When non-empty the agent materializes them at /skill inside
	// the container (via the Docker copy API — works whether the agent runs
	// on the host or as a sibling container) and Volumes is ignored. Old
	// agents ignore this field and fall back to Volumes.
	Files map[string]string `json:"files"`
}

// Limits on inline skill files (decoded).
const (
	MaxSkillFiles     = 64
	MaxSkillFileBytes = 5 * 1024 * 1024 // 5 MB total decoded
)

// skillFilesMountPoint is where inline files land inside the container,
// matching the manifest command convention `python /skill/run.py`.
const skillFilesMountPoint = "/skill"

// ValidateSkillFiles checks inline skill files for path traversal, count and
// size limits. Returns a descriptive error suitable for a 400 response.
func ValidateSkillFiles(files map[string]string) error {
	if len(files) == 0 {
		return nil
	}
	if len(files) > MaxSkillFiles {
		return fmt.Errorf("too many skill files: %d (max %d)", len(files), MaxSkillFiles)
	}
	var total int64
	for name, b64 := range files {
		if err := validateSkillFilePath(name); err != nil {
			return err
		}
		content, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("skill file %q: invalid base64: %w", name, err)
		}
		total += int64(len(content))
		if total > MaxSkillFileBytes {
			return fmt.Errorf("skill files exceed %d bytes decoded", MaxSkillFileBytes)
		}
	}
	return nil
}

// validateSkillFilePath rejects absolute paths, traversal, and anything that
// doesn't survive filepath.Clean unchanged.
func validateSkillFilePath(name string) error {
	if name == "" {
		return fmt.Errorf("skill file with empty path")
	}
	if strings.Contains(name, "\\") {
		return fmt.Errorf("skill file %q: backslash not allowed", name)
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return fmt.Errorf("skill file %q: absolute paths not allowed", name)
	}
	clean := filepath.Clean(name)
	if clean != name {
		return fmt.Errorf("skill file %q: non-canonical path", name)
	}
	if clean == ".." || strings.HasPrefix(clean, "../") || clean == "." {
		return fmt.Errorf("skill file %q: path traversal not allowed", name)
	}
	return nil
}

// buildSkillFilesArchive validates files and produces a tar archive rooted at
// "skill/" for injection at "/" via CopyToContainer. Directories 0755,
// files 0644, deterministic entry order.
func buildSkillFilesArchive(files map[string]string) (*bytes.Buffer, error) {
	if err := ValidateSkillFiles(files); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	now := time.Now()

	// Emit directory entries (root + each unique parent), sorted so
	// parents precede children.
	dirs := map[string]bool{"skill": true}
	for _, name := range names {
		d := filepath.Dir(name)
		for d != "." {
			dirs["skill/"+d] = true
			d = filepath.Dir(d)
		}
	}
	dirNames := make([]string, 0, len(dirs))
	for d := range dirs {
		dirNames = append(dirNames, d)
	}
	sort.Strings(dirNames)
	for _, d := range dirNames {
		if err := tw.WriteHeader(&tar.Header{
			Name:     d + "/",
			Typeflag: tar.TypeDir,
			Mode:     0o755,
			ModTime:  now,
		}); err != nil {
			return nil, fmt.Errorf("tar dir %s: %w", d, err)
		}
	}

	for _, name := range names {
		content, err := base64.StdEncoding.DecodeString(files[name])
		if err != nil {
			return nil, fmt.Errorf("skill file %q: invalid base64: %w", name, err)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     "skill/" + name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(content)),
			ModTime:  now,
		}); err != nil {
			return nil, fmt.Errorf("tar header %s: %w", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, fmt.Errorf("tar write %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("tar close: %w", err)
	}
	return buf, nil
}

// ── Skill-run request validation ────────────────────────────────────────────
//
// Everything below exists because /api/skills/run takes a container spec from
// the data plane. Any peer holding the fleet cluster secret can reach it, and
// the container's stdout comes back in the response — so an unconstrained
// spec is a read primitive over this node's whole filesystem. The single
// request that motivated this file:
//
//	{"image":"busybox","command":["sh","-c","cat /h/etc/noo-node-agent.env"],
//	 "volumes":{"/":"/h"}}
//
// one call, and the caller holds this node's cluster secret, NATS credential,
// agent token and private node key. ReadOnly does not help: the payload is
// secrets at rest, not a write.
//
// The shape of the answer is host_ops.go's: the DATA PLANE PROPOSES, THE
// LOCAL BINARY CONSTRAINS. What a bind source may point at is compiled in
// (plus operator env), never taken from the request.

// skillBindRootEnvs are the env vars whose values become allowed bind roots.
// NOO_SKILLS_HOST_DIR is the host view of the skills tree — the ONE legitimate
// legacy mount (`{skill_dir: "/skill"}`, controller-local; every current
// caller ships the same bytes inline as `files` instead). NOO_DATA_ROOT is the
// node's data tree. NOO_SKILL_BIND_ROOTS is the operator's escape hatch for a
// site that keeps skills somewhere else: colon-separated absolute paths, read
// from THIS process's environment, so widening it takes a node-local config
// change and a restart — not a request field.
var skillBindRootEnvs = []string{"NOO_SKILLS_HOST_DIR", "NOO_DATA_ROOT"}

const skillBindRootsEnv = "NOO_SKILL_BIND_ROOTS"

// skillBindRoots returns the canonicalized roots a bind source may live under.
// Empty means no bind mount is accepted at all — the safe end state for a node
// that was never configured for the legacy transport.
func skillBindRoots() []string {
	var raw []string
	for _, k := range skillBindRootEnvs {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			raw = append(raw, v)
		}
	}
	for _, v := range filepath.SplitList(os.Getenv(skillBindRootsEnv)) {
		if v = strings.TrimSpace(v); v != "" {
			raw = append(raw, v)
		}
	}
	roots := make([]string, 0, len(raw))
	for _, r := range raw {
		clean, err := canonicalHostPath(r)
		if err != nil {
			// A misconfigured root is dropped, loudly: silently treating
			// "/" or a typo as a root is how this hole would come back.
			slog.Warn("skill: ignoring unusable bind root", "root", r, "error", err)
			continue
		}
		if err := hostDirAllowed(clean); err != nil {
			slog.Warn("skill: ignoring bind root that names a system path", "root", r, "error", err)
			continue
		}
		roots = append(roots, clean)
	}
	return roots
}

// canonicalHostPath resolves p to an absolute, symlink-free, lexically clean
// path. Both the root and the requested source go through it before they are
// compared: a raw string prefix test is defeated by "/skills/../etc" and by a
// symlink planted inside the skills tree, and either one puts the check back
// to where it started. EvalSymlinks needs the path to exist; a source that
// doesn't is refused anyway (Docker would fail the create, or worse,
// auto-create it as an empty root-owned dir).
func canonicalHostPath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("empty path")
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q is not absolute", p)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("path %q does not resolve on this host: %w", p, err)
	}
	clean := filepath.Clean(resolved)
	if clean == "/" {
		return "", fmt.Errorf("path %q resolves to the filesystem root", p)
	}
	return clean, nil
}

// pathWithin reports whether p is root itself or lives under it. Both
// arguments must already be canonical — the boundary is a path SEPARATOR, so
// "/data-evil" is not inside "/data".
func pathWithin(root, p string) bool {
	if root == p {
		return true
	}
	return strings.HasPrefix(p, strings.TrimSuffix(root, "/")+string(filepath.Separator))
}

// validateSkillVolumes canonicalizes every bind source and refuses — never
// silently drops — one that falls outside the allowed roots. A dropped mount
// would leave the caller staring at a missing /skill with no explanation, and
// an operator cannot fix a misconfiguration that produces no message.
func validateSkillVolumes(volumes map[string]string) error {
	if len(volumes) == 0 {
		return nil
	}
	roots := skillBindRoots()
	if len(roots) == 0 {
		return fmt.Errorf("bind mounts are not permitted on this node: no skill bind root configured "+
			"(set NOO_SKILLS_HOST_DIR, NOO_DATA_ROOT or %s in the agent environment) — "+
			"ship the skill inline via the `files` field instead", skillBindRootsEnv)
	}
	for hostPath, containerPath := range volumes {
		if strings.TrimSpace(containerPath) == "" || !strings.HasPrefix(containerPath, "/") {
			return fmt.Errorf("bind target %q must be an absolute path in the container", containerPath)
		}
		clean, err := canonicalHostPath(hostPath)
		if err != nil {
			return fmt.Errorf("refusing bind source %q: %w", hostPath, err)
		}
		if err := hostDirAllowed(clean); err != nil {
			return fmt.Errorf("refusing bind source %q: %w", hostPath, err)
		}
		var ok bool
		for _, root := range roots {
			if pathWithin(root, clean) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("refusing bind source %q (resolves to %s): outside the allowed skill bind roots %s",
				hostPath, clean, strings.Join(roots, ", "))
		}
	}
	return nil
}

// validateSkillImage refuses an empty or obviously bogus image reference.
// Deliberately NOT a registry allow-list: which registries a fleet trusts is
// an operator policy decision, and inventing one here would silently break
// nodes that pull from their own mirror. See the PR that added this for the
// follow-up.
func validateSkillImage(image string) error {
	img := strings.TrimSpace(image)
	if img == "" {
		return fmt.Errorf("image is required")
	}
	if img != image {
		return fmt.Errorf("image %q has leading or trailing whitespace", image)
	}
	if len(img) > 512 {
		return fmt.Errorf("image reference is implausibly long (%d bytes)", len(img))
	}
	// A reference is registry/name[:tag][@digest]; none of these may appear.
	// Shell metacharacters in particular have no business in a name we hand
	// to the daemon and echo into logs.
	for _, r := range img {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._-:/@", r):
		default:
			return fmt.Errorf("image %q contains an invalid character %q", image, r)
		}
	}
	if strings.HasPrefix(img, "-") {
		return fmt.Errorf("image %q may not start with '-'", image)
	}
	return nil
}

// ValidateSkillRunRequest is the whole admission decision for a skill run,
// called by the handler so a bad spec is a 400 before any container work.
func ValidateSkillRunRequest(req *SkillRunRequest) error {
	if req == nil {
		return fmt.Errorf("empty request")
	}
	// The container name reaches ContainerStop/ContainerRemove(Force) and
	// ContainerCreate. Unvalidated, `container_name: "noo-gateway"` — or
	// any other name on this host — was a force-remove of whatever the
	// caller pointed at, from a route that is otherwise a sandbox.
	if err := ValidateManagedContainerName(req.ContainerName); err != nil {
		return err
	}
	if err := validateSkillImage(req.Image); err != nil {
		return err
	}
	// network_mode: "host" hands the container this node's loopback — every
	// service that trusts 127.0.0.1 (the agent's own API among them) and the
	// host's whole network namespace. A sandbox that can dial localhost is
	// not a sandbox. The gateway and CLI only ever send "none", "bridge" or
	// a named restricted network.
	if strings.EqualFold(strings.TrimSpace(req.NetworkMode), "host") {
		return fmt.Errorf(`network_mode "host" is refused for skill containers: ` +
			`it would put the sandbox on this node's loopback, in reach of every ` +
			`service that trusts 127.0.0.1 — use "none" or a named network`)
	}
	if err := ValidateSkillFiles(req.Files); err != nil {
		return err
	}
	// Only validate binds that will actually be used: inline Files win.
	if len(req.Files) == 0 {
		if err := validateSkillVolumes(req.Volumes); err != nil {
			return err
		}
	}
	return nil
}

// skillRunUser is the uid[:gid] a skill container runs as. Root inside the
// container plus a bind mount (or a kernel bug) is a materially bigger blast
// radius than the job needs: skill code reads /skill and writes its own temp
// files. 65534 (nobody) exists in every base image we ship. Overridable for a
// skill image that genuinely needs a different uid; "" restores the image's
// own default, which is a deliberate operator choice, not a request field.
func skillRunUser() string {
	if v, ok := os.LookupEnv("NOO_SKILL_RUN_USER"); ok {
		return strings.TrimSpace(v)
	}
	return "65534:65534"
}

// skillPidsLimit caps process creation inside the sandbox: a fork bomb in a
// skill must not take the node's other backends down with it.
const skillPidsLimit int64 = 256

// SkillFloorHostConfig is THE sandbox floor, in one place.
//
// It was inline in RunSkillContainer, and for one caller that was fine. It is
// exported and shared now because a SECOND kind of third-party program runs on
// a node — a node-local stdio MCP server — and the argument for
// giving it the same floor is only as strong as the two configurations being
// literally the same object. A copy would drift, and the drift would be
// silent: both containers would still start.
//
// Applied to EVERY such container regardless of what the spec asked for:
//
//	no-new-privileges  setuid binaries in the image cannot buy root back past
//	                   the non-root user the caller sets (SkillRunUser)
//	CapDrop ALL        no kernel capabilities at all
//	PidsLimit          a fork bomb cannot take this node's backends with it
//
// The caller adds memory, network and mounts on top; it must not remove any of
// these.
func SkillFloorHostConfig() *container.HostConfig {
	pidsLimit := skillPidsLimit
	return &container.HostConfig{
		SecurityOpt: []string{"no-new-privileges"},
		CapDrop:     []string{"ALL"},
		Resources:   container.Resources{PidsLimit: &pidsLimit},
	}
}

// SkillRunUser exports skillRunUser so a second caller under the same floor
// runs as the same non-root user, decided by the same node-local variable.
func SkillRunUser() string { return skillRunUser() }

// SkillRunResult is the response returned to the gateway after skill execution.
type SkillRunResult struct {
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ExitCode    int    `json:"exit_code"`
	ContainerID string `json:"container_id"`
}

// RunSkillContainer pulls (if needed), creates, starts, waits for, and collects
// output from a skill container. This is a synchronous call — it blocks until
// the container exits or the timeout fires.
func (c *Client) RunSkillContainer(req SkillRunRequest) (*SkillRunResult, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	// Re-validate at the door of the only function that creates a container.
	// The handler already did this; RunSkillContainer must not depend on
	// that, because the day a second caller appears the checks would be gone.
	if err := ValidateManagedContainerName(req.ContainerName); err != nil {
		return nil, err
	}
	if err := validateSkillImage(req.Image); err != nil {
		return nil, err
	}

	// Inline skill files (preferred over Volumes): validate and build the
	// tar archive up front so bad payloads fail before any container work.
	var filesArchive *bytes.Buffer
	if len(req.Files) > 0 {
		var err error
		filesArchive, err = buildSkillFilesArchive(req.Files)
		if err != nil {
			return nil, fmt.Errorf("skill files: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+30)*time.Second)
	defer cancel()

	// The image, over the artifact rail (image_source.go).
	if err := ensureImageFn(ctx, c, req.Image); err != nil {
		return nil, fmt.Errorf("skill %s image: %w", req.ContainerName, err)
	}

	// Remove existing container with same name if present
	_, _ = c.docker.ContainerStop(ctx, req.ContainerName, client.ContainerStopOptions{})
	_, _ = c.docker.ContainerRemove(ctx, req.ContainerName, client.ContainerRemoveOptions{Force: true})

	// Build environment list
	env := make([]string, 0, len(req.Env))
	for k, v := range req.Env {
		env = append(env, k+"="+v)
	}

	// Container config
	containerCfg := &container.Config{
		Image: req.Image,
		Cmd:   req.Command,
		Env:   env,
		// Non-root by default — see skillRunUser.
		User: skillRunUser(),
		Labels: map[string]string{
			"noo.managed-by": "node-agent-go",
			"noo.skill":      "true",
		},
	}

	// Host config. The floor — no-new-privileges, CapDrop ALL, a pid cap —
	// now lives in SkillFloorHostConfig, because the node-local MCP transport
	// runs under the SAME object rather than a copy of it.
	hostCfg := SkillFloorHostConfig()

	// Memory limit (parse Docker-style "256m", "1g", etc.)
	if memBytes := parseMemoryLimit(req.MemoryLimit); memBytes > 0 {
		hostCfg.Resources.Memory = memBytes
	}

	// Network mode. "host" is NOT reachable here — ValidateSkillRunRequest
	// refuses it up front (it would put the sandbox on this node's loopback);
	// this second check is the belt to that braces, for any future caller
	// that reaches RunSkillContainer without going through the handler.
	if strings.EqualFold(strings.TrimSpace(req.NetworkMode), "host") {
		return nil, fmt.Errorf(`network_mode "host" is refused for skill containers`)
	}
	if req.NetworkMode == "none" {
		hostCfg.NetworkMode = container.NetworkMode(req.NetworkMode)
	}
	// For named networks like "noo-skill-restricted" or "bridge", attach via NetworkingConfig

	// GPU reservation
	if req.GPU {
		hostCfg.Resources.DeviceRequests = []container.DeviceRequest{
			{
				Driver:       "nvidia",
				Capabilities: [][]string{{"gpu"}},
				Count:        1,
			},
		}
	}

	// Volumes (host_path -> container_path) — legacy controller-local
	// bind mounts. Skipped when inline Files are provided: the bind source
	// generally doesn't exist on this node's host filesystem.
	//
	// The source is NOT what the caller wrote: validateSkillVolumes has
	// already canonicalized it and proved it lives under an allowed root, and
	// we mount the canonical form so the daemon resolves exactly the path we
	// checked rather than re-walking symlinks we already followed.
	if len(req.Volumes) > 0 && filesArchive == nil {
		if err := validateSkillVolumes(req.Volumes); err != nil {
			return nil, err
		}
		mounts := make([]mount.Mount, 0, len(req.Volumes))
		for hostPath, containerPath := range req.Volumes {
			source, err := canonicalHostPath(hostPath)
			if err != nil {
				return nil, fmt.Errorf("refusing bind source %q: %w", hostPath, err)
			}
			mounts = append(mounts, mount.Mount{
				Type:     mount.TypeBind,
				Source:   source,
				Target:   containerPath,
				ReadOnly: true,
			})
		}
		hostCfg.Mounts = mounts
	}

	// Network config (for named networks)
	networkCfg := &network.NetworkingConfig{}
	if req.NetworkMode != "" && req.NetworkMode != "none" && req.NetworkMode != "host" {
		networkCfg.EndpointsConfig = map[string]*network.EndpointSettings{
			req.NetworkMode: {},
		}
	}

	// Create container
	resp, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:           containerCfg,
		HostConfig:       hostCfg,
		NetworkingConfig: networkCfg,
		Name:             req.ContainerName,
	})
	if err != nil {
		return nil, fmt.Errorf("create skill container %s: %w", req.ContainerName, err)
	}
	containerID := resp.ID

	slog.Info("skill: container created", "container", req.ContainerName, "id", containerID[:12])

	// Materialize inline skill files at /skill before start. CopyToContainer
	// works regardless of where the agent itself runs (host or sibling
	// container) and needs no host temp dir; the files vanish with the
	// container (removed below on every path).
	if filesArchive != nil {
		if _, err := c.docker.CopyToContainer(ctx, containerID, client.CopyToContainerOptions{
			DestinationPath: "/",
			Content:         filesArchive,
		}); err != nil {
			_, _ = c.docker.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{Force: true})
			return nil, fmt.Errorf("copy skill files into %s: %w", req.ContainerName, err)
		}
		slog.Info("skill: files materialized", "container", req.ContainerName,
			"files", len(req.Files), "target", skillFilesMountPoint)
	}

	// Start container
	if _, err := c.docker.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		// Clean up on failure
		_, _ = c.docker.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{Force: true})
		return nil, fmt.Errorf("start skill container %s: %w", req.ContainerName, err)
	}

	// Wait for container to exit (with timeout)
	waitCtx, waitCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer waitCancel()

	waitRes := c.docker.ContainerWait(waitCtx, containerID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	statusCh, errCh := waitRes.Result, waitRes.Error
	var exitCode int64

	select {
	case status := <-statusCh:
		exitCode = status.StatusCode
	case err := <-errCh:
		if err != nil {
			// Timeout or other error — kill the container
			slog.Warn("skill: container wait error, killing", "container", req.ContainerName, "error", err)
			killCtx, killCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer killCancel()
			_, _ = c.docker.ContainerKill(killCtx, containerID, client.ContainerKillOptions{Signal: "SIGKILL"})
			exitCode = -1
		}
	case <-waitCtx.Done():
		// Timeout
		slog.Warn("skill: container timed out", "container", req.ContainerName, "timeout", timeout)
		killCtx, killCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer killCancel()
		_, _ = c.docker.ContainerKill(killCtx, containerID, client.ContainerKillOptions{Signal: "SIGKILL"})
		exitCode = -1
	}

	// Collect stdout and stderr
	stdout, stderr := c.collectContainerOutput(ctx, containerID)

	// Remove the container (cleanup)
	removeCtx, removeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer removeCancel()
	_, _ = c.docker.ContainerRemove(removeCtx, containerID, client.ContainerRemoveOptions{Force: true})

	slog.Info("skill: container finished",
		"container", req.ContainerName,
		"exit_code", exitCode,
		"stdout_len", len(stdout),
	)

	return &SkillRunResult{
		Stdout:      stdout,
		Stderr:      stderr,
		ExitCode:    int(exitCode),
		ContainerID: containerID[:12],
	}, nil
}

// collectContainerOutput reads stdout and stderr from a stopped container.
func (c *Client) collectContainerOutput(ctx context.Context, containerID string) (string, string) {
	// Stdout
	stdoutReader, err := c.docker.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: false,
	})
	var stdout string
	if err == nil {
		defer stdoutReader.Close()
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, stdoutReader)
		stdout = stripDockerLogHeaders(buf.String())
	}

	// Stderr
	stderrReader, err := c.docker.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: false,
		ShowStderr: true,
	})
	var stderr string
	if err == nil {
		defer stderrReader.Close()
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, stderrReader)
		stderr = stripDockerLogHeaders(buf.String())
	}

	return stdout, stderr
}

// stripDockerLogHeaders removes the 8-byte Docker multiplexed stream headers
// from each line of container log output.
func stripDockerLogHeaders(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if len(line) > 8 && line[0] <= 2 {
			lines[i] = line[8:]
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// parseMemoryLimit converts Docker-style memory strings ("256m", "1g") to bytes.
func parseMemoryLimit(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0
	}

	var multiplier int64 = 1
	if strings.HasSuffix(s, "g") {
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") {
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "k") {
		multiplier = 1024
		s = s[:len(s)-1]
	}

	var n int64
	fmt.Sscanf(s, "%d", &n)
	return n * multiplier
}
