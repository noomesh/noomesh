// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlenv"
	"github.com/noomesh/noomesh/node-agent-go/internal/sidecarimage"
)

// The stunnel sidecar: the client-certificate door for every agent-started
// backend (llama.cpp, ollama, TEI, the reranker, and vLLM since door
// generation 5 — its own TLS listener could not pin callers by name). One shape, reused per backend, the same shape the compose
// stack runs on the controller (docker/Dockerfile.stunnel +
// docker/stunnel-<x>.conf, `verify = 2`): the sidecar presents the
// backend's service leaf, verifies every caller against the cluster CA,
// REQUIRES a client certificate, and forwards plaintext to the backend.
//
// The plaintext hop never leaves the door (door generation 3, followup 1234
// F-ii). The backend container joins the sidecar's network namespace
// (NetworkMode `container:noo-stunnel-<x>`) and listens on 127.0.0.1 only
// (privateDoorEnv); the sidecar accepts on its own bridge address (its
// hostname) and connects to 127.0.0.1. No other container on the bridge
// and no host process can reach the plain port: the sidecar is the only
// door. Until generation 3 the backend sat
// on the bridge beside its sidecar and any peer could dial it plain.
//
// One namespace has one owner. The sidecar owns it, because stunnel is
// tiny and does not crash under load; an engine that restarts (an OOM, the
// GPU watchdog) rejoins it. A sidecar that restarts leaves the engine in
// the old, dead namespace: readDeclaredTLS records that as a backend_door
// row and HealStrandedEngines restarts the engine on the next reconcile.
//
// The conf is not a host file. The agent runs as an unprivileged host
// process and owns no directory a root-in-container sidecar should read a
// conf from, so the conf travels in STUNNEL_CONF and the sidecar's
// entrypoint writes it to its own /tmp before exec'ing stunnel.

// BackendDoorGeneration is folded into the reconciler's spec hash
// (reconcile.specHash) so that a backend container created by an agent
// with an OLDER door shape is recreated ONCE, on the first reconcile tick
// after the agent binary rolls, with no placement edit. Bump it when the
// door a backend is created with changes shape; a bump recreates every
// placed backend on every node (a cold model load each).
//
//	1  the pre-door shape (vLLM plain unless NOO_VLLM_TLS, no sidecars)
//	2  2026-09-29: vLLM --ssl-cert-reqs 2 unconditional; stunnel sidecars
//	   (verify = 2) beside llama.cpp, ollama, TEI and the reranker
//	3  2026-10-28: the fronted backend inside its sidecar's network
//	   namespace on 127.0.0.1; the sidecar the only door (F-ii)
//	4  2026-10-28: the door admits its callers by name (checkHost: this
//	   node's own agent leaf + the controller's service callers), not any
//	   cluster-CA leaf (i301, internal#300). No node ran 3 (dev only), so a
//	   0.6.13 node still recreates each fronted backend once.
//	5  2026-10-28: vLLM behind noo-stunnel-vllm too (alias noo-vllm, so the
//	   URL and the leaf are unchanged), plain on 127.0.0.1 inside it: its own
//	   listener admitted any cluster-CA leaf. No node ran 4 either.
const BackendDoorGeneration = 5

// doorCallers are the leaf names a backend door admits besides this node's
// own agent: the same list as the compose doors (docker/stunnel-<x>.conf,
// i132). Those leaves exist only on the controller, so on any other node
// only the agent's own leaf opens its doors; another node's leaf, an
// add-on's or a backend's chains to the same CA and is refused at the
// handshake.
var doorCallers = []string{"gateway", "worker", "trellion", "trellion-intel", "evolve"}

// doorSelfName is the name this node's agent leaf is pinned by: its first
// DNS SAN, the node id (noo-cli pki.rs issue_node_cert puts it first). Read
// from the leaf the agent presents (NOO_TLS_CERT), not from NODE_ID, which
// may be "auto". The other node SANs (localhost, node-agent) every node leaf
// carries, so they are never a pin. Swapped in tests.
var doorSelfName = func() (string, error) {
	path := ctrlenv.TLSCert()
	if path == "" {
		return "", fmt.Errorf("NOO_TLS_CERT is unset: the door pins this node's agent leaf by name and has none to read")
	}
	names, err := leafDNSNames(path)
	if err != nil {
		return "", fmt.Errorf("read this node's leaf %s: %w", path, err)
	}
	if len(names) == 0 {
		return "", fmt.Errorf("this node's leaf %s carries no DNS name to pin", path)
	}
	return checkDoorPin(names[0])
}

// checkDoorPin refuses a name that is shared by every node leaf or that
// could break out of its conf line.
func checkDoorPin(name string) (string, error) {
	if name == "" || name == "localhost" || name == "node-agent" {
		return "", fmt.Errorf("this node's leaf names %q first, which every node leaf carries; reissue it with `noo cluster provision <node>`", name)
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return "", fmt.Errorf("this node's leaf name %q is not a plain node name", name)
		}
	}
	return name, nil
}

// doorLoopback is the only address a fronted backend listens on.
const doorLoopback = "127.0.0.1"

// DoorNetworkMode is the network mode a fronted backend is created with:
// its sidecar's namespace. "" for a backend with no sidecar.
func DoorNetworkMode(backend string) string {
	if sc := SidecarContainerFor(backend); sc != "" {
		return "container:" + sc
	}
	return ""
}

// privateDoorEnv pins a fronted backend's listener to loopback, in every
// spelling the engines read: llama-server (HOST for the noo image's
// wrapper, LLAMA_ARG_HOST/PORT for upstream), ollama (OLLAMA_HOST), TEI
// (HOSTNAME, its --hostname; docker otherwise fills it with the namespace
// owner's hostname, which resolves to the bridge address). Setting all of
// them on every fronted engine is harmless and keeps the rule one line.
// Applied after every placement override, so no env can put a backend
// back on the bridge.
func privateDoorEnv(port int) map[string]string {
	p := strconv.Itoa(port)
	return map[string]string{
		"HOST":           doorLoopback,
		"LLAMA_ARG_HOST": doorLoopback,
		"LLAMA_ARG_PORT": p,
		"OLLAMA_HOST":    doorLoopback + ":" + p,
		"HOSTNAME":       doorLoopback,
	}
}

// StunnelImageEnv overrides the sidecar image on a node.
const StunnelImageEnv = "STUNNEL_IMAGE"

// stunnelFallbackImage is used when no built stunnel image is reachable:
// plain alpine, with stunnel installed by the entrypoint at first start
// (apk, ~1 MB). The release matrix publishes a multi-arch stunnel image
// (#552), and NOO_IMAGE_PREFIX/stunnel:NOO_IMAGE_TAG wins below; this is
// kept for nodes on a release that predates it, reported on the heartbeat
// (`stunnel_image`, internal/sidecarimage) and removed once every node
// carries the published image.
const stunnelFallbackImage = "alpine:3.22"

// stunnelSidecarScript is the sidecar's `sh -c` entrypoint. `command -v`
// covers the built image (docker/Dockerfile.stunnel, stunnel on PATH); the
// apk arm covers the alpine fallback.
const stunnelSidecarScript = `
command -v stunnel >/dev/null 2>&1 || apk add --no-cache stunnel >/dev/null
printf '%s\n' "$STUNNEL_CONF" > /tmp/stunnel.conf
exec stunnel /tmp/stunnel.conf
`

// sidecarUser is the user the agent-started door runs as: root, explicitly,
// whatever the image's USER says (see startSidecar).
const sidecarUser = "0"

// SidecarLabel marks a sidecar container with the backend it fronts.
const SidecarLabel = "noo.sidecar-for"

// stunnelConf renders the sidecar's stunnel.conf: the same keys as
// docker/stunnel-<x>.conf. It accepts on acceptHost — the sidecar's own
// hostname, i.e. its bridge address, NOT 0.0.0.0, which would also claim
// 127.0.0.1:<port> where the backend listens when the two ports are equal
// (llama.cpp 8085, ollama 11434) — and connects to the backend on loopback
// inside the shared namespace. `verify = 2` is the whole point — it is what
// makes the sidecar a door and not a TLS wrapper — and the checkHost lines
// make it a door for named callers only: stunnel accepts a peer when ANY
// of them matches a DNS SAN of its leaf. selfName is this node's agent
// leaf name (doorSelfName); doorCallers follow it.
func stunnelConf(service, acceptHost string, acceptPort, connectPort int, selfName string) string {
	var pins strings.Builder
	for _, n := range append([]string{selfName}, doorCallers...) {
		fmt.Fprintf(&pins, "checkHost = %s\n", n)
	}
	return fmt.Sprintf(`; generated by noo-node-agent — the client-certificate door for %s
foreground = yes
pid =

[%s]
accept = %s:%d
connect = %s:%d
cert = /tls/services/%s/service.crt
key = /tls/services/%s/service.key
CAfile = /tls/ca.crt
verify = 2
%s`, service, service, acceptHost, acceptPort, doorLoopback, connectPort, service, service, pins.String())
}

// stunnelImageCandidates lists the images to try, in order, for a
// backend's sidecar. A pinned door (door_images.go) has no fallback after
// its pin: falling back would move the door off the image it is pinned to,
// so a pin that is not staged fails the start, naming the image.
func stunnelImageCandidates(backend string) []string {
	var out []string
	if v := strings.TrimSpace(os.Getenv(StunnelImageEnv)); v != "" {
		out = append(out, v)
	}
	if ref := pinnedDoorFetchRef(backend); ref != "" {
		return append(out, ref)
	}
	prefix, tag := os.Getenv("NOO_IMAGE_PREFIX"), os.Getenv("NOO_IMAGE_TAG")
	if prefix != "" && tag != "" {
		out = append(out, prefix+"/stunnel:"+tag)
	}
	// The compose-built name: present on a controller and on any node
	// `sync-images` shipped it to.
	out = append(out, "noomesh/stunnel:latest", stunnelFallbackImage)
	return out
}

// ensureSidecarImage returns the first sidecar image that is present
// locally or can be pulled, trying stunnelImageCandidates in order.
func (c *Client) ensureSidecarImage(ctx context.Context, backend string) (string, error) {
	var errs []string
	for _, img := range stunnelImageCandidates(backend) {
		// Local-or-rail for the published stunnel image; the alpine
		// fallback is a public third-party image, so it may come from its
		// registry only under NOO_IMAGE_REGISTRY_FALLBACK (image_source.go).
		if err := ensureImageFn(ctx, c, img); err != nil {
			errs = append(errs, img+": "+err.Error())
			continue
		}
		// The fallback is logged ONCE per process and carried on every
		// heartbeat as `stunnel_image` (internal/sidecarimage), so the
		// controller sees a node whose doors depend on the alpine mirror.
		sidecarimage.Chose(img, img == stunnelFallbackImage, errs)
		return img, nil
	}
	return "", fmt.Errorf("no stunnel image available (%s)", strings.Join(errs, "; "))
}

// sidecarConnectPort is the port the backend container listens on behind
// its door: the placement's PORT if it set one, else the spec's, else the
// door table's default. The reranker's depends on its engine (llama-server
// 8085, TEI 80) and the spec says which.
func sidecarConnectPort(backend string, spec BackendSpec, envOverrides map[string]string) int {
	if v, ok := envOverrides["PORT"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	if v, ok := spec.Env["PORT"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(resolveEnv(v))); err == nil && n > 0 {
			return n
		}
	}
	if backend == "reranker" && spec.Env["MODEL_ID"] != "" {
		return 80 // TEI engine
	}
	return backendDoors[backend].PlainPort
}

// startSidecar creates and starts noo-stunnel-<svc> for a backend, on the
// backend's network (under the door's Alias too, when it has one), BEFORE
// the backend (which joins its namespace), with the same privilege floor as the backends
// (no-new-privileges, CapDrop ALL) plus what stunnel-as-root actually
// needs: DAC_OVERRIDE to read the 0600 leaf key on the bind mount, and
// NET_BIND_SERVICE only for a door below 1024 (the TEI/reranker doors on
// 443, the port compose's stunnel-tei.conf accepts on).
func (c *Client) startSidecar(ctx context.Context, backend, image, networkName string, connectPort int) error {
	door := backendDoors[backend]
	name := SidecarContainerFor(backend)
	self, err := doorSelfName()
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	conf := stunnelConf(door.Sidecar, name, door.Port, connectPort, self)
	mounts := []mount.Mount{
		{Type: mount.TypeBind, Source: resolveEnv(pkiCACertSource), Target: "/tls/ca.crt", ReadOnly: true},
		{Type: mount.TypeBind, Source: resolveEnv(pkiServiceLeafSource(door.Sidecar)), Target: "/tls/services/" + door.Sidecar, ReadOnly: true},
	}
	caps := []string{"DAC_OVERRIDE"}
	if door.Port < 1024 {
		caps = append(caps, "NET_BIND_SERVICE")
	}
	cfg := &container.Config{
		Image: image,
		// Root ON PURPOSE (and spelled out): the published stunnel image ends
		// `USER 65532` since i132, but this door reads the node's root-owned
		// 0600 leaf under /etc/noo/pki through the DAC_OVERRIDE cap below, and
		// the alpine fallback's entrypoint runs `apk add`. Without this, a
		// node pulling the new image would start a door that cannot read its key.
		User: sidecarUser,
		// The name the conf accepts on: docker writes it into /etc/hosts
		// with the bridge address, so stunnel binds that and leaves
		// loopback to the backend.
		Hostname:   name,
		Env:        []string{"STUNNEL_CONF=" + conf},
		Entrypoint: []string{"sh", "-c"},
		Cmd:        []string{stunnelSidecarScript},
		Labels: map[string]string{
			"com.docker.compose.project": "pai-assistant",
			"noo.managed-by":             "node-agent-go",
			SidecarLabel:                 backend,
		},
	}
	hostCfg := &container.HostConfig{
		Mounts:        mounts,
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		SecurityOpt:   []string{"no-new-privileges"},
		CapDrop:       []string{"ALL"},
		CapAdd:        caps,
	}
	// macOS: the door (this sidecar's accept port) on host loopback only —
	// the agent cannot route to a Docker Desktop bridge IP (LoopbackDoorPublish).
	if LoopbackDoorPublish() {
		applyLoopbackDoor(cfg, hostCfg, door.Port)
	}
	netCfg := &network.NetworkingConfig{}
	if networkName != "" {
		ep := &network.EndpointSettings{}
		// The name callers already dial (vLLM: noo-vllm). The engine of
		// that name joins no network, so docker DNS answers the alias with
		// the door's address and nothing else.
		if door.Alias != "" {
			ep.Aliases = []string{door.Alias}
		}
		netCfg.EndpointsConfig = map[string]*network.EndpointSettings{networkName: ep}
	}
	resp, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: cfg, HostConfig: hostCfg, NetworkingConfig: netCfg, Name: name,
	})
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	if _, err := c.docker.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	slog.Info("backend door started", "backend", backend, "sidecar", name, "image", image, "dial", doorDialHost(backend),
		"accept", fmt.Sprintf("%s:%d", name, door.Port), "connect", fmt.Sprintf("%s:%d", doorLoopback, connectPort))
	return nil
}

// removeSidecar stops and removes a backend's sidecar if it exists.
func (c *Client) removeSidecar(ctx context.Context, backend string) {
	name := SidecarContainerFor(backend)
	if name == "" {
		return
	}
	timeout := 5
	_, _ = c.docker.ContainerStop(ctx, name, client.ContainerStopOptions{Timeout: &timeout})
	_, _ = c.docker.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true})
}

// ReleaseSidecarImage is the door sidecar image this node runs for backend
// when that image is pinned by this node's own configuration: STUNNEL_IMAGE,
// else the backend's door pin (door_images.go: vLLM's, by tag AND digest,
// so the hash moves when the pin does and never on a release roll alone),
// else its release ref NOO_IMAGE_PREFIX/stunnel:NOO_IMAGE_TAG. "" for a
// backend with no sidecar, and for a node with none of these (the
// compose-built name and the alpine fallback do not move with a release).
//
// The reconciler folds it into the spec hash (reconcile.specHash): the
// sidecar is recreated with its backend, and until 2026-10-28 nothing in the
// hash moved when only the node's release did, so a stack roll left
// noo-stunnel-llamacpp on the previous release's image.
func ReleaseSidecarImage(backend string) string {
	if SidecarContainerFor(backend) == "" {
		return ""
	}
	if v := strings.TrimSpace(os.Getenv(StunnelImageEnv)); v != "" {
		return v
	}
	if ref := pinnedDoorRef(backend); ref != "" {
		return ref
	}
	prefix, tag := os.Getenv("NOO_IMAGE_PREFIX"), os.Getenv("NOO_IMAGE_TAG")
	if prefix == "" || tag == "" {
		return ""
	}
	return prefix + "/stunnel:" + tag
}
