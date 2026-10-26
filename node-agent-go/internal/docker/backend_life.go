// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

// Backend container life. `noo cluster verify`'s node
// `backend doors` row is judged from the heartbeat, and the controller
// never runs `docker inspect` on a node. So the first verify
// after a bundle apply read a backend that was still warming up as a
// failed door, and the operator was sent after a certificate problem that
// did not exist. The agent now says, per running backend container, when
// it started and what its healthcheck says; the heartbeat carries it as
//
//	"backend_containers": {
//	  "vllm": {"running": true, "started_at": 1790000000, "health": "starting",
//	           "telemetry_missing": []},
//	  "embedding": {"running": true, "started_at": 1789990000,
//	                "telemetry_missing": ["HF_HUB_DISABLE_TELEMETRY"]}
//	}
//
// keyed exactly like `running_backends`. `health` is omitted when the
// container declares no healthcheck. The CLI may read a door miss as
// `starting` only from this report, and only inside its warm-up window;
// a controller that gets no report changes nothing.
//
// When the backend is served by the agent's ADOPTED lane (the self-node's
// stack ollama, a Mac's native ollama) and a docker container for the same
// key also runs, that container is nobody's: the reconciler never converges
// an adopted backend, so it never receives a switch the agent stamps. Its
// entry then also carries
//
//	"orphan": true, "container": "noo-ollama", "sidecars": ["noo-stunnel-ollama"]
//
// (`sidecars` only when one runs). Additive: an older controller ignores the
// keys. The agent removes nothing; the operator does, from `noo cluster
// verify`'s `vendor telemetry` row.
//
// `telemetry_missing` names the vendor telemetry switches (telemetry.go)
// the running container's env lacks; `noo cluster verify`'s node
// `vendor telemetry` row FAILs on any.

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// containerLife is one backend container's entry in `backend_containers`.
// nil when the state carries no parseable start time: a start time is the
// whole point, and a guessed one would widen the warm-up window.
func containerLife(st *container.State) map[string]any {
	if st == nil {
		return nil
	}
	started, err := time.Parse(time.RFC3339Nano, st.StartedAt)
	if err != nil || started.IsZero() || started.Year() < 2000 {
		return nil
	}
	out := map[string]any{"running": st.Running, "started_at": started.Unix()}
	if st.Health != nil {
		if h := strings.TrimSpace(string(st.Health.Status)); h != "" && h != string(container.NoHealthcheck) {
			out["health"] = h
		}
	}
	return out
}

// BackendContainers is the heartbeat's `backend_containers`: backend key ->
// containerLife, for every running PAI backend container (stunnel sidecars
// and rename-orphans excluded, as in RunningBackends). nil when docker
// cannot be listed — the heartbeat then omits the key, which reads as "not
// reported", never as "nothing is starting". `{}` is a real report.
func (c *Client) BackendContainers(ctx context.Context) map[string]any {
	return c.BackendContainersBeside(ctx, nil)
}

// BackendContainersBeside is BackendContainers with the backend keys an
// adopted lane serves: a docker container for such a key is flagged orphan
// (see the file comment). adopted may be nil.
func (c *Client) BackendContainersBeside(ctx context.Context, adopted map[string]bool) map[string]any {
	if c == nil || c.docker == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil
	}
	out := map[string]any{}
	sidecars := map[string][]string{}
	for _, ctr := range containers {
		if len(ctr.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(ctr.Names[0], "/")
		if sk := stunnelBackendKey(name); sk != "" {
			sidecars[sk] = append(sidecars[sk], name)
			continue
		}
		key := backendKeyFromName(name)
		if key == "" {
			continue
		}
		res, err := c.docker.ContainerInspect(ctx, ctr.ID, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		if life := containerLife(res.Container.State); life != nil {
			// The vendor telemetry switches this container lacks, by NAME
			// (docs/security/telemetry.md). Always present on a report from
			// an agent that knows the switches — `[]` is a proof, and an
			// absent key reads as "agent predates the report".
			var env []string
			if res.Container.Config != nil {
				env = res.Container.Config.Env
			}
			life["telemetry_missing"] = TelemetryMissing(key, env)
			life["container"] = name
			// The ref the container was CREATED from, and whether it can move
			// under it (no digest, tag latest or none, not one of our rail
			// images). A container an older agent made before the floating-
			// ref refusal keeps running on it; `noo cluster verify` names it.
			if res.Container.Config != nil {
				life["image"], life["image_floating"] = imageFacts(res.Container.Config.Image)
			}
			out[key] = life
		}
	}
	markOrphans(out, sidecars, adopted)
	return out
}

// imageFacts is the heartbeat's `image` / `image_floating` for one backend
// container's `Config.Image`.
func imageFacts(img string) (string, bool) {
	return img, isFloatingRef(img) && !isOwnImage(img)
}

// stunnelBackendKey is the backend a stunnel sidecar fronts ("noo-stunnel-
// ollama" -> "ollama"), "" when name is no sidecar or fronts none.
func stunnelBackendKey(name string) string {
	if !strings.Contains(name, "stunnel") {
		return ""
	}
	return backendKeyFromName(strings.Replace(name, "stunnel", "", 1))
}

// markOrphans flags every report entry whose backend key an adopted lane
// serves. The sidecars listed are those fronting the same key.
func markOrphans(out map[string]any, sidecars map[string][]string, adopted map[string]bool) {
	for key, v := range out {
		if !adopted[key] {
			continue
		}
		life, ok := v.(map[string]any)
		if !ok {
			continue
		}
		life["orphan"] = true
		if sc := sidecars[key]; len(sc) > 0 {
			sort.Strings(sc)
			life["sidecars"] = sc
		}
	}
}
