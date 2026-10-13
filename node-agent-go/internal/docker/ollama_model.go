// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Importing a converted model into this node's ollama, over the pull rail.
//
// `noo cluster ship-model` used to do this with `scp` and two `ssh` calls: it
// copied a GGUF and a Modelfile into ~/model-ship and ran `ollama create`
// there. Both halves were wrong in different ways — the copy duplicated
// `preseedGGUF`, which had been fetching digest-verified GGUFs from the same
// store for months, and the `ssh` needed a transport the mesh retired
//
// The verb takes a NAME and nothing else. That is the same shape every other
// pull kind has, and it is deliberate: a Modelfile is a recipe the daemon
// executes, so an endpoint that accepted one in the request body would be a
// remote-execution endpoint. The agent fetches BOTH files from the
// controller's store by name and verifies both digests before ollama is told
// anything.
package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/client"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// OllamaContainer is the container `ollama create` runs in when the node has
// no host binary — the same name BackendManager gives it.
const OllamaContainer = "noo-ollama"

// convertDir is where the Modelfile and its weight are placed INSIDE the
// ollama container. `FROM ./<file>` resolves relative to the Modelfile, so
// the two must share one directory whatever the path is.
const convertDir = "/convert"

// PullOllamaModelResult reports what actually happened on the node.
type PullOllamaModelResult struct {
	Status string `json:"status"`
	Model  string `json:"model"`
	GGUF   string `json:"gguf"`
	// "host" (an ollama binary on PATH) or "container" (noo-ollama).
	Via string `json:"via"`
}

// safeArtifactName mirrors the gateway's `valid_artifact_name`: a name is a
// single path component, never a traversal. The gateway rejects these too;
// checking here as well means a node is not relying on the controller having
// done it, which is the posture every other agent-side allowlist takes.
func safeArtifactName(name string) bool {
	return name != "" &&
		len(name) < 256 &&
		!strings.ContainsAny(name, "/\\") &&
		!strings.Contains(name, "..") &&
		!strings.HasPrefix(name, ".")
}

// modelfileWeight reads the weight filename out of a Modelfile's FROM line.
//
// The convert script writes `FROM ./<name>-<quant>.gguf`, so the weight's
// name is NOT derivable from the model name — it has to be read. Everything
// else in the file (TEMPLATE, PARAMETER) is ollama's business, not ours.
//
// A FROM naming anything but a bare .gguf filename is refused rather than
// resolved: `FROM /etc/shadow` and `FROM ../../x` are the reason this
// function exists at all, and `FROM llama3` (a registry pull) is a different
// operation that this verb does not perform.
func modelfileWeight(body string) (string, error) {
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		ref := strings.Trim(fields[1], `"'`)
		ref = strings.TrimPrefix(ref, "./")
		if !strings.HasSuffix(strings.ToLower(ref), ".gguf") {
			return "", fmt.Errorf("Modelfile FROM names %q, which is not a .gguf weight — this verb imports a converted weight, it does not pull from a registry", fields[1])
		}
		if !safeArtifactName(ref) {
			return "", fmt.Errorf("Modelfile FROM names %q, which is not a bare filename", fields[1])
		}
		return ref, nil
	}
	return "", fmt.Errorf("Modelfile has no FROM line")
}

// PullOllamaModel fetches <name>.Modelfile and the weight it names from the
// controller's GGUF store, then runs `ollama create <name>`.
//
// Digests are REQUIRED for both, unlike `preseedGGUF`'s best-effort posture.
// preseed is a fast path with a working fallback — a miss means the backend
// downloads from HuggingFace instead. This is an operator command with no
// fallback, and what it hands ollama is a recipe the daemon executes, so
// "the controller could not tell me what these bytes should be" is a refusal
// rather than a reason to proceed.
func (c *Client) PullOllamaModel(ctx context.Context, name string) (*PullOllamaModelResult, error) {
	// No Docker check here: a node serving ollama natively (a Mac with no
	// Docker) imports through the host binary below, and reconcile calls
	// this for such a node too. Only the container path needs Docker.
	if !safeArtifactName(name) {
		return nil, fmt.Errorf("model name %q is not a single path component", name)
	}
	cacheURL := preseed.CacheURL()
	if cacheURL == "" {
		return nil, fmt.Errorf("NOO_MODEL_CACHE_URL is not set — no data plane to pull from")
	}

	work, err := os.MkdirTemp(stagingDir(), "ollama-model-")
	if err != nil {
		// stagingDir may not exist yet on a node that has never pulled.
		if mkErr := os.MkdirAll(stagingDir(), 0o755); mkErr != nil {
			return nil, fmt.Errorf("create staging dir %s: %w", stagingDir(), mkErr)
		}
		if work, err = os.MkdirTemp(stagingDir(), "ollama-model-"); err != nil {
			return nil, fmt.Errorf("create work dir: %w", err)
		}
	}
	// Multi-GB weights: never leave one behind because a create failed.
	defer func() { _ = os.RemoveAll(work) }()

	fetch := func(kind, artifact string) (string, error) {
		// The GGUF behind a Modelfile can be GBs: wait out the gateway's hash.
		m, err := awaitArtifactManifest(ctx, kind, artifact)
		if errors.Is(err, ErrArtifactAbsent) {
			return "", fmt.Errorf(
				"no artifact manifest for %s/%s — the controller store does not have it, or this gateway predates the %s kind; run `noo cluster ship-model` from the controller",
				kind, artifact, kind)
		}
		if err != nil {
			// Not "absent": the controller was not heard from. Saying the
			// store lacks the file here sends the operator to re-ship bytes
			// that are already there.
			return "", fmt.Errorf("could not get the artifact manifest for %s/%s from the controller: %w", kind, artifact, err)
		}
		dest := filepath.Join(work, artifact)
		src := cacheURL + "/gguf/" + url.PathEscape(artifact)
		fetchCtx, cancel := context.WithTimeout(ctx, 60*time.Minute)
		defer cancel()
		if _, err := preseed.New().FetchOneVerified(fetchCtx, src, dest, m.SHA256); err != nil {
			return "", fmt.Errorf("fetch %s: %w", artifact, err)
		}
		return dest, nil
	}

	mfName := name + ".Modelfile"
	mfPath, err := fetch("modelfile", mfName)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(mfPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mfName, err)
	}
	weight, err := modelfileWeight(string(body))
	if err != nil {
		return nil, err
	}
	if _, err := fetch("gguf", weight); err != nil {
		return nil, err
	}
	slog.Info("ollama model staged", "model", name, "weight", weight, "work", work)

	// Host binary first: a node running ollama natively has no noo-ollama
	// container to copy into, and this is the cheaper path when it exists.
	if bin, ok := ollamaBinary(); ok {
		if out, runErr := runOllamaCreate(ctx, bin, work, name, mfName); runErr != nil {
			return nil, fmt.Errorf("ollama create failed on the host binary: %s", out)
		}
		return &PullOllamaModelResult{Status: "created", Model: name, GGUF: weight, Via: "host"}, nil
	}

	if c == nil || c.docker == nil {
		return nil, fmt.Errorf("no `ollama` binary on this node and Docker is not available to run it in %s", OllamaContainer)
	}
	out, err := c.ollamaCreateInContainer(ctx, work, name, mfName, weight)
	if err != nil {
		return nil, err
	}
	slog.Info("ollama model created", "model", name, "via", "container", "detail", lastLine(out))
	return &PullOllamaModelResult{Status: "created", Model: name, GGUF: weight, Via: "container"}, nil
}

// ModelInStore asks the controller's store whether it publishes
// `<name>.Modelfile` — the recipe `noo cluster import-model` (and reconcile,
// for a placed import-only model) imports from. A model the store publishes
// is import-only: it is not on the public registry, so `ollama pull` for it
// can never succeed.
//
// (true, nil): the store has it. (false, nil): the store answered that it
// does not, or the name cannot be a store artifact (a registry tag such as
// `llama3.2:1b`). (false, err): the question went unanswered — a timeout or
// a transport failure — and the caller must not read that as either answer.
func ModelInStore(ctx context.Context, name string) (bool, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ":latest")
	if !safeArtifactName(name) || strings.Contains(name, ":") {
		return false, nil
	}
	_, err := lookupArtifactManifest(ctx, "modelfile", name+".Modelfile")
	if errors.Is(err, ErrArtifactAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ImportOllamaModel is reconcile's entry to the import-model path: the same
// fetch-verify-create as `noo cluster import-model`, for a placed model the
// node's ollama does not hold yet.
func (c *Client) ImportOllamaModel(ctx context.Context, name string) (string, error) {
	res, err := c.PullOllamaModel(ctx, name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s created from %s via %s", res.Model, res.GGUF, res.Via), nil
}

// isRunning reports whether a named container exists and is up. A stopped
// noo-ollama is not an error to fix here: BackendManager owns bringing
// backends up, and starting one as a side effect of importing a model would
// be a second thing this verb does without being asked.
func (c *Client) isRunning(ctx context.Context, name string) bool {
	res, err := c.docker.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	return err == nil && res.Container.State != nil && res.Container.State.Running
}

// ollamaHostPaths are where a native ollama lives when the agent's PATH does
// not say: a launchd- or systemd-started agent gets a minimal PATH without
// Homebrew's prefix, so `exec.LookPath` alone missed the ollama a Mac node
// was serving from /opt/homebrew/bin (live, host6 2026-10-09: import-model
// answered "no `ollama` binary" while ollama served chat).
var ollamaHostPaths = []string{
	"/opt/homebrew/bin/ollama", // Homebrew, Apple Silicon
	"/usr/local/bin/ollama",    // Homebrew on Intel macOS; the Linux install script
	"/usr/bin/ollama",          // distro packages
}

// ollamaBinary finds the host's ollama: PATH first, then the known install
// locations. A path counts only if it is an executable regular file.
func ollamaBinary() (string, bool) {
	if bin, err := exec.LookPath("ollama"); err == nil {
		return bin, true
	}
	for _, p := range ollamaHostPaths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

func runOllamaCreate(ctx context.Context, bin, dir, name, modelfile string) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin, "create", name, "-f", modelfile)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ollamaCreateInContainer copies the staged pair into noo-ollama and runs
// `ollama create` there.
//
// The container mounts only its own data dir, so the node's staging area is
// not visible inside it — the files have to be copied in. They land in one
// directory because `FROM ./<file>` is resolved relative to the Modelfile.
func (c *Client) ollamaCreateInContainer(ctx context.Context, work, name, modelfile, weight string) (string, error) {
	if !c.isRunning(ctx, OllamaContainer) {
		return "", fmt.Errorf(
			"no `ollama` binary on this node and the %s container is not running — start it (`noo cluster start-backend %s ollama`) or install ollama, then re-run",
			OllamaContainer, os.Getenv("NODE_ID"))
	}
	tarball, err := dirTar(work, []string{modelfile, weight})
	if err != nil {
		return "", fmt.Errorf("assemble copy archive: %w", err)
	}
	copyCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if _, err := c.docker.CopyToContainer(copyCtx, OllamaContainer, client.CopyToContainerOptions{
		DestinationPath: "/",
		Content:         tarball,
	}); err != nil {
		return "", fmt.Errorf("copy the model into %s: %w", OllamaContainer, err)
	}
	created, err := c.docker.ExecCreate(copyCtx, OllamaContainer, client.ExecCreateOptions{
		Cmd:          []string{"ollama", "create", name, "-f", modelfile},
		WorkingDir:   convertDir,
		AttachStdout: true,
		AttachStderr: true,
		// One undemultiplexed stream: the output is an operator's error
		// message, not something to parse.
		TTY: true,
	})
	if err != nil {
		return "", fmt.Errorf("exec create: %w", err)
	}
	att, err := c.docker.ExecAttach(copyCtx, created.ID, client.ExecAttachOptions{TTY: true})
	if err != nil {
		return "", fmt.Errorf("exec attach: %w", err)
	}
	raw, _ := io.ReadAll(att.Reader)
	att.Close()
	out := strings.TrimSpace(string(raw))
	ins, err := c.docker.ExecInspect(copyCtx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("exec inspect: %w", err)
	}
	// The exec's own exit code, not the copy's success — `ollama create`
	// fails on a bad Modelfile long after every transfer reported fine.
	if ins.ExitCode != 0 {
		return out, fmt.Errorf("ollama create exited %d in %s: %s", ins.ExitCode, OllamaContainer, lastLine(out))
	}
	return out, nil
}

// dirTar packs named files from dir into the tar CopyToContainer wants,
// rooted so they extract into convertDir.
func dirTar(dir string, names []string) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	root := strings.TrimPrefix(convertDir, "/")
	if err := tw.WriteHeader(&tar.Header{
		Name:     root + "/",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
		ModTime:  time.Unix(0, 0),
	}); err != nil {
		return nil, err
	}
	for _, n := range names {
		body, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:    root + "/" + n,
			Mode:    0o644,
			Size:    int64(len(body)),
			ModTime: time.Unix(0, 0),
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}
