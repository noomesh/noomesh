// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package docker provides Docker container management for the node agent.
//
// It wraps the Docker Engine API client to handle backend lifecycle,
// container stats collection, and log retrieval.
package docker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"

	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// BackendPorts maps backend names to their default ports.
// Matches Python gateway.constants.BACKEND_PORTS.
var BackendPorts = map[string]int{
	"vllm":      8000,
	"llamacpp":  8085,
	"ollama":    11434,
	"airllm":    8000,
	"embedding": 8082,
}

// BackendURL returns the intra-cluster URL of a backend's DOOR as it is
// declared for the compose stack (aliases a containerised agent resolves).
// Agent-started backends and the controller's own host agent go through
// BackendDialURL, which reads the running containers instead.
func BackendURL(backend, _ string) string {
	switch backend {
	case "ollama":
		// A HOST-installed agent has no compose DNS: on a standalone
		// controller the only ollama is the embed container, published on
		// loopback, and the agent env says where (OLLAMA_URL). The stunnel
		// alias stays the default for containerised worker agents. Without
		// this every inference job dispatched to the controller's own node
		// died on "lookup stunnel-ollama: server misbehaving".
		if u := strings.TrimRight(os.Getenv("OLLAMA_URL"), "/"); u != "" {
			return u
		}
		return "https://stunnel-ollama:11434"
	case "embedding", "tei":
		return "https://stunnel-tei:443"
	}
	return backendDialURL(backend, nil)
}

// backendTLSEnvVars is config.BackendTLSFlags: the per-backend variables
// provision renders. They switch nothing any more (see there); SchemeFor
// answers https for every backend named in it.
var backendTLSEnvVars = nodeconfig.BackendTLSFlags

// SchemeFor returns the scheme an agent-started backend's door serves:
// https for every backend the agent fronts with a required client
// certificate (vLLM natively, the rest behind a stunnel sidecar — see
// backendDoors), http only for a backend that is neither, which today is
// airllm alone (the same named exception the compose side carries:
// tests/test_backend_listeners_require_client_certs.py PLAINTEXT_EXCEPTIONS).
//
// The NOO_<BACKEND>_TLS flags used to be the switch here; a value of
// false/0/no/off now refuses the agent's START (config.TLSServerConfig),
// so by the time this runs there is nothing left for them to say.
func SchemeFor(backend string) string {
	if _, ok := backendTLSEnvVars[backend]; ok {
		return "https"
	}
	return "http"
}

// StunnelLlamacppContainer fronts llama.cpp with mTLS (compose:
// docker/stunnel-llamacpp.conf; agent-started: the sidecar this package
// runs), `verify = 2`: llama-server has no TLS listener of its own. A
// caller that sees this container running dials it — on llama.cpp's own
// port — with a client certificate.
const StunnelLlamacppContainer = "noo-stunnel-llamacpp"

// StunnelContainerPrefix names every stunnel sidecar, compose-run or
// agent-run: noo-stunnel-<service>. The compose container_name is
// `${NOO_CONTAINER_PREFIX:-noo}-stunnel-<x>` and the agent uses the same
// names, so ONE declaration read covers both stacks and the controller's
// service leaves (SANs noo-stunnel-<x>, onboard steps.rs) verify against
// either.
const StunnelContainerPrefix = "noo-stunnel-"

// VLLMClientCertFlag is what every vLLM in the cluster runs with
// (`--ssl-cert-reqs 2`, ssl.CERT_REQUIRED): the listener is TLS and refuses
// a caller without a cluster-CA client certificate. Its presence in a
// container's command is the container declaring "dial me over TLS, with
// your leaf"; a vLLM created before 2026-09-29 by an older agent lacks it
// and is dialled plain until the reconciler recreates it (backends.go
// backendDoorGeneration).
const VLLMClientCertFlag = "--ssl-cert-reqs"

// backendDoor is how a caller reaches one backend on the docker bridge.
type backendDoor struct {
	// Sidecar is the stunnel service name (`noo-stunnel-<Sidecar>`) when
	// the backend cannot terminate TLS itself; "" when it serves natively
	// (vLLM) or, for airllm, serves plaintext by named exception.
	Sidecar string
	// Port the door listens on. For a sidecar it is the port compose's
	// stunnel-<x>.conf accepts on, so the same URL reaches a compose door
	// and an agent-run one.
	Port int
	// PlainPort is the backend's own listener behind the door (what the
	// sidecar forwards to; the port an undeclared, pre-door container is
	// dialled on during the transition).
	PlainPort int
}

// backendDoors is the node-side door table — the counterpart of
// tests/test_backend_listeners_require_client_certs.py BACKEND_SERVICES on
// the compose side, and pinned to it by
// tests/test_node_backends_require_client_certs.py. A backend absent here
// is dialled plain on BackendPorts (airllm; nothing else).
var backendDoors = map[string]backendDoor{
	"vllm":           {Port: 8000, PlainPort: 8000},
	"vllm-secondary": {Port: 8000, PlainPort: 8000},
	"llamacpp":       {Sidecar: "llamacpp", Port: 8085, PlainPort: 8085},
	"ollama":         {Sidecar: "ollama", Port: 11434, PlainPort: 11434},
	"embedding":      {Sidecar: "tei", Port: 443, PlainPort: 80},
	"reranker":       {Sidecar: "reranker", Port: 443, PlainPort: 8085},
}

// SidecarFor returns the stunnel service name fronting a backend ("" when
// the backend serves TLS natively or is not fronted).
func SidecarFor(backend string) string {
	return backendDoors[backend].Sidecar
}

// SidecarContainerFor returns the sidecar container name for a fronted
// backend, "" otherwise.
func SidecarContainerFor(backend string) string {
	if sc := SidecarFor(backend); sc != "" {
		return StunnelContainerPrefix + sc
	}
	return ""
}

// DoorPort returns the port a backend's door listens on (0 = no door).
func DoorPort(backend string) int { return backendDoors[backend].Port }

// sidecarBackend maps a running sidecar container name back to the backend
// key it fronts ("" for a name that is not a known sidecar). The compose
// stack runs `noo-stunnel-tei-gpu` for its GPU TEI: same backend.
func sidecarBackend(name string) string {
	if !strings.HasPrefix(name, StunnelContainerPrefix) {
		return ""
	}
	svc := strings.TrimSuffix(strings.TrimPrefix(name, StunnelContainerPrefix), "-gpu")
	for backend, d := range backendDoors {
		if d.Sidecar != "" && d.Sidecar == svc {
			return backend
		}
	}
	return ""
}

// declaredTLS is what the RUNNING containers say about how their backends
// must be dialled, as opposed to what this agent's env says. The compose-run
// backends on a controller and the agent-started ones on a node carry the
// same declaration: vLLM in its command line (VLLMClientCertFlag), every
// other backend by a `noo-stunnel-<x>` container beside it. A running
// backend with NEITHER is a pre-door container — created by an older agent,
// or by compose before 2026-09-28 — and is the one case still dialled plain:
// readDeclaredTLS records a refusal row for it so `cluster verify` shows
// the plaintext door until the reconciler recreates the backend.
type declaredTLS struct {
	tls      map[string]bool // backend key -> the listener requires TLS (+ client cert)
	sidecars map[string]bool // backend key -> its noo-stunnel-<x> is running
	known    map[string]bool // backend key -> a container for it is running
	// stranded: backend key -> engine container ID, for a fronted engine
	// whose sidecar restarted after it (sidecar.go): it sits in the old
	// namespace, unreachable, until HealStrandedEngines restarts it.
	stranded map[string]string
}

// engineDoorShape is how a fronted engine sits relative to its door.
type engineDoorShape int

const (
	engineInDoor   engineDoorShape = iota // in its sidecar's namespace, started after it
	engineOnBridge                        // its own network: any bridge peer dials it plain
	engineStranded                        // in the namespace of a sidecar that restarted since
)

// judgeEngineDoor is the pure decision behind the generation-3 rows:
// netMode is the engine's HostConfig.NetworkMode, sidecarIDs the running
// sidecars' ID -> name, startedAt the inspected start times (RFC 3339)
// of the engine and of the sidecar it names, "" when unknown.
func judgeEngineDoor(netMode string, sidecarIDs map[string]string, engineStarted, sidecarStarted string) (engineDoorShape, string) {
	ref, ok := strings.CutPrefix(netMode, "container:")
	if !ok {
		return engineOnBridge, ""
	}
	sidecarID := ""
	for id, name := range sidecarIDs {
		if id == ref || name == ref || (len(ref) >= 12 && strings.HasPrefix(id, ref)) {
			sidecarID = id
		}
	}
	if sidecarID == "" {
		// The namespace owner is gone or is not a door: nothing reaches
		// the engine through a sidecar, which is the stranded case.
		return engineStranded, ""
	}
	e, errE := time.Parse(time.RFC3339Nano, engineStarted)
	sc, errS := time.Parse(time.RFC3339Nano, sidecarStarted)
	if errE == nil && errS == nil && sc.After(e) {
		return engineStranded, sidecarID
	}
	return engineInDoor, sidecarID
}

// DeclaredTLS reads the declaration off the running containers. Cached for
// a few seconds: the inference proxy asks per request and the answer only
// changes when a container is (re)created. Nil when the daemon could not
// be listed — the caller then dials the door an agent-started backend is
// created with (TLS), never a guessed plaintext one.
func (c *Client) DeclaredTLS(ctx context.Context) *declaredTLS {
	c.declMu.Lock()
	defer c.declMu.Unlock()
	if c.declRead && time.Now().Before(c.declExpires) {
		return c.decl
	}
	d := c.readDeclaredTLS(ctx)
	if ctx.Err() != nil {
		// The caller went away mid-read: the nil is its cancellation, not
		// the daemon's answer, so it must not be cached for the next caller.
		return d
	}
	c.decl = d
	c.declRead = true
	c.declExpires = time.Now().Add(10 * time.Second)
	return c.decl
}

func (c *Client) readDeclaredTLS(ctx context.Context) *declaredTLS {
	d := &declaredTLS{tls: map[string]bool{}, sidecars: map[string]bool{}, known: map[string]bool{}, stranded: map[string]string{}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil
	}
	sidecarIDs := map[string]string{} // running sidecar ID -> name
	engines := map[string]container.Summary{}
	for _, ctr := range containers {
		if len(ctr.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(ctr.Names[0], "/")
		if b := sidecarBackend(name); b != "" {
			d.sidecars[b] = true
			sidecarIDs[ctr.ID] = name
			continue
		}
		key := backendKeyFromName(name)
		if key == "" {
			continue
		}
		d.known[key] = true
		if SidecarFor(key) != "" {
			engines[key] = ctr
		}
		if key != "vllm" && key != "vllm-secondary" {
			continue
		}
		res, err := c.docker.ContainerInspect(ctx, ctr.ID, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		if commandDeclaresClientCert(res.Container.Config.Entrypoint, res.Container.Config.Cmd) {
			d.tls[key] = true
		}
	}
	// The plaintext-door row: a running backend that should have a door
	// (backendDoors) and declares none. Loud on the node's heartbeat and
	// in `noo cluster verify`, cleared the moment the door appears.
	for key := range backendDoors {
		if d.known[key] && d.sidecars[key] && SidecarFor(key) != "" {
			c.judgeFrontedEngine(ctx, d, key, engines[key], sidecarIDs)
			continue
		}
		if !d.known[key] || d.tls[key] || d.sidecars[key] {
			refusals.Clear("backend_door", key)
			continue
		}
		refusals.Record("backend_door", key,
			"the running "+ContainerNameFor(key)+" serves PLAINTEXT on the docker bridge (no "+
				VLLMClientCertFlag+" in its command / no "+StunnelContainerPrefix+SidecarFor(key)+
				" beside it): it predates the client-certificate door and this agent dials it plain "+
				"until the reconciler recreates it — which needs this node's services/"+doorLeafService(key)+
				" leaf under $NOO_PKI_DIR (backend_start/backend_tls rows say if it is missing)")
	}
	return d
}

// judgeFrontedEngine records (or clears) the backend_door row for an
// engine whose sidecar runs: door generation 3 wants it inside the
// sidecar's namespace on loopback (sidecar.go). An engine on the bridge
// beside its door predates generation 3 and is reachable plain by every
// bridge peer until the reconciler recreates it; a stranded one answers
// nobody until HealStrandedEngines restarts it.
func (c *Client) judgeFrontedEngine(ctx context.Context, d *declaredTLS, key string, eng container.Summary, sidecarIDs map[string]string) {
	started := func(id string) string {
		res, err := c.docker.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil || res.Container.State == nil {
			return ""
		}
		return res.Container.State.StartedAt
	}
	netMode := eng.HostConfig.NetworkMode
	engStarted, scStarted := "", ""
	if ref, ok := strings.CutPrefix(netMode, "container:"); ok {
		engStarted = started(eng.ID)
		scStarted = started(ref)
	}
	shape, _ := judgeEngineDoor(netMode, sidecarIDs, engStarted, scStarted)
	name := ContainerNameFor(key)
	switch shape {
	case engineOnBridge:
		refusals.Record("backend_door", key,
			"the running "+name+" listens on the docker bridge beside "+SidecarContainerFor(key)+
				": every container on the bridge (and host processes) can call it PLAINTEXT, without a certificate. "+
				"It predates door generation 3 (the backend inside its door's network, on 127.0.0.1); "+
				"the reconciler recreates it on its next pass")
	case engineStranded:
		d.stranded[key] = eng.ID
		refusals.Record("backend_door", key,
			"the running "+name+" is cut off: "+SidecarContainerFor(key)+" restarted after it, and "+name+
				" still sits in the old network namespace, so its door reaches nothing. "+
				"The reconciler restarts "+name+" on its next pass")
	default:
		refusals.Clear("backend_door", key)
	}
}

// HealStrandedEngines restarts every fronted engine left in a dead
// namespace by a sidecar restart (sidecar.go). An engine restart rejoins
// the sidecar's current namespace; it costs a model load, which is what
// the engine needs anyway to be reachable again. Returns the restarted
// container names.
func (c *Client) HealStrandedEngines(ctx context.Context) []string {
	if c == nil || c.docker == nil {
		return nil
	}
	c.declMu.Lock()
	d := c.readDeclaredTLS(ctx)
	c.declRead = false // the restarts below change the answer
	c.declMu.Unlock()
	if d == nil {
		return nil
	}
	var out []string
	for key, id := range d.stranded {
		name := ContainerNameFor(key)
		timeout := 10
		if _, err := c.docker.ContainerRestart(ctx, id, client.ContainerRestartOptions{Timeout: &timeout}); err != nil {
			slog.Warn("door: could not restart a stranded backend", "backend", key, "container", name, "error", err)
			continue
		}
		slog.Warn("door: restarted a backend stranded by its sidecar's restart", "backend", key, "container", name,
			"sidecar", SidecarContainerFor(key))
		out = append(out, name)
	}
	return out
}

// doorLeafService names the service leaf a backend's door serves with:
// `vllm` for vLLM's own listener, the sidecar's service name otherwise.
func doorLeafService(backend string) string {
	if sc := SidecarFor(backend); sc != "" {
		return sc
	}
	return "vllm"
}

// commandDeclaresClientCert: the joined entrypoint + command names
// VLLMClientCertFlag. A vLLM's command is one `sh -c` script, so the flag
// sits inside a single argument; a substring match is the honest read of it.
func commandDeclaresClientCert(entrypoint, cmd []string) bool {
	joined := strings.Join(append(append([]string{}, entrypoint...), cmd...), " ")
	return strings.Contains(joined, VLLMClientCertFlag)
}

// BackendDialURL is the URL this agent dials for a backend, with the
// running containers' own declaration applied: a vLLM whose command
// carries the client-cert flag over https, a backend whose sidecar runs AT
// the sidecar, an undeclared pre-door container plain (recorded, see
// readDeclaredTLS), and with no readable declaration the TLS door every
// agent-started backend is created with. The caller's transport must
// present the node leaf for any https door (config.HTTPTransport does; the
// inference proxy's httpsTransport does since 2026-09-28).
func (c *Client) BackendDialURL(ctx context.Context, backend string) string {
	if c == nil {
		return backendDialURL(backend, nil)
	}
	return backendDialURL(backend, c.DeclaredTLS(ctx))
}

// backendDialURL is the pure decision behind BackendDialURL.
func backendDialURL(backend string, d *declaredTLS) string {
	if backend == "ollama" {
		if u := strings.TrimRight(os.Getenv("OLLAMA_URL"), "/"); u != "" {
			return u
		}
	}
	door, hasDoor := backendDoors[backend]
	if !hasDoor {
		port := BackendPorts[backend]
		if port == 0 {
			port = 8000
		}
		return fmt.Sprintf("%s://noo-%s:%d", SchemeFor(backend), backend, port)
	}
	if d != nil {
		switch {
		case d.sidecars[backend]:
			return fmt.Sprintf("https://%s%s:%d", StunnelContainerPrefix, door.Sidecar, door.Port)
		case d.tls[backend]:
			return fmt.Sprintf("https://noo-%s:%d", backend, door.Port)
		case d.known[backend]:
			// Pre-door container: dial what runs (the row is recorded).
			name := ContainerNameFor(backend)
			if name == "" {
				name = "noo-" + backend
			}
			return fmt.Sprintf("http://%s:%d", name, door.PlainPort)
		}
	}
	if door.Sidecar != "" {
		return fmt.Sprintf("https://%s%s:%d", StunnelContainerPrefix, door.Sidecar, door.Port)
	}
	return fmt.Sprintf("https://noo-%s:%d", backend, door.Port)
}

// ProfileMap maps backend names to docker-compose profiles.
var ProfileMap = map[string]string{
	"vllm":      "vllm",
	"llamacpp":  "llamacpp",
	"ollama":    "ollama",
	"airllm":    "airllm",
	"embedding": "embedding",
}

// EnvVarNames maps backend names to model environment variable names.
var EnvVarNames = map[string]string{
	"vllm":      "VLLM_MODEL",
	"llamacpp":  "LLAMACPP_MODEL",
	"ollama":    "OLLAMA_MODEL",
	"airllm":    "AIRLLM_MODEL",
	"embedding": "EMBEDDING_MODEL",
}

// Client wraps the Docker Engine API client with node-agent specific operations.
type Client struct {
	docker         *client.Client
	httpClient     *http.Client // for querying backends (e.g., Ollama /api/ps)
	scheme         string       // "http" or "https"
	composeProject string       // scope container listings to this compose project

	// What the running containers declare about their listeners
	// (DeclaredTLS), cached briefly.
	declMu      sync.Mutex
	decl        *declaredTLS
	declRead    bool
	declExpires time.Time
}

// NewClient creates a new Docker client wrapper. composeProject scopes stats
// and listings to a single compose stack via the com.docker.compose.project
// label — pass "" to disable the filter and see every container on the host.
// pingDocker is a short, bounded reachability probe. Kept separate so tests can
// exercise NewClient's decision without a daemon.
var pingDocker = func(dc *client.Client) error {
	// Process startup (NewClient): there is no caller ctx yet; bounded at 5s.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dc.Ping(ctx, client.PingOptions{})
	return err
}

// inContainer reports whether this process is running inside a container.
//
// /.dockerenv is written by the Docker daemon into every container it creates;
// the cgroup check catches the podman/containerd cases. Both are heuristics, so
// a false NEGATIVE degrades to the host behaviour (a warning), never to a
// spurious refusal to start.
var inContainer = func() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		c := string(b)
		if strings.Contains(c, "docker") || strings.Contains(c, "containerd") ||
			strings.Contains(c, "libpod") {
			return true
		}
	}
	return false
}

// NewClient builds the docker client. sensorProxy marks a tier-5 companion
// (sensor proxy): its job never involves backend management, and its
// container deliberately mounts NO docker.sock (least privilege — the
// separation is enforced by what isn't mounted, docker-compose
// node-agent-sensors). For it, an unreachable docker is the EXPECTED state,
// not a misconfiguration — warn and continue instead of refusing to start
// (hit live 2026-08-28: the host9-sensors recreate crash-looped on the
// in-container fatal below).
func NewClient(httpClient *http.Client, scheme, composeProject string, sensorProxy bool) (*Client, error) {
	dc, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("creating docker client: %w", err)
	}

	// NewClientWithOpts does not connect — it builds a client that fails later,
	// on every call. So check reachability now, while there is somewhere useful
	// to report it.
	//
	// This exists because the design removed docker.sock from the
	// node-agent compose service. The service is opt-in
	// (`--profile node-agent-compose`; the `worker` compose profile is gone
	// since fleet logging phase 4), so a deployment that selects it can still
	// start this agent IN A CONTAINER with no socket. Without this check it would come up, serve :8081, answer
	// health, register with the controller — and fail every backend operation.
	// "Starts cleanly and is silently useless" is the exact failure shape this
	// codebase has now hit three times (401 registration, NATS auth, TLS CA).
	//
	// In a container: FATAL. A containerised node-agent that cannot reach
	// Docker has no purpose — managing containers IS the job — so refusing to
	// start is both correct and the loudest possible signal.
	//
	// On a host: WARN only. The agent runs natively on macOS specifically to
	// drive a native Metal Ollama with no Docker involved, and on Linux it may
	// legitimately start before dockerd. Refusing there would break supported
	// deployments to no benefit.
	if pingErr := pingDocker(dc); pingErr != nil {
		host := os.Getenv("DOCKER_HOST")
		if host == "" {
			host = "unix:///var/run/docker.sock (default)"
		}
		if inContainer() && !sensorProxy {
			return nil, fmt.Errorf(
				"docker is unreachable at %s and this agent is running IN A CONTAINER "+
					"(%w). A containerised node-agent exists to manage containers, so it "+
					"cannot do anything useful without the Docker API. The docker.sock "+
					"mount was removed from the node-agent compose service, "+
					"and the service left the default compose profiles on 2026-09-04 — "+
					"this node should run the agent as a HOST PROCESS instead, which is "+
					"what the pull rail installs: `noo cluster bootstrap-token create "+
					"--node <node>`, run the printed one-liner on the node, then "+
					"`noo cluster provision <node> --wait`", host, pingErr)
		}
		slog.Warn("docker is unreachable — backend management will fail until it is up",
			"docker_host", host, "error", pingErr)
	}

	return &Client{
		docker:         dc,
		httpClient:     httpClient,
		scheme:         scheme,
		composeProject: composeProject,
	}, nil
}

// Reachable reports whether the Docker daemon answers right now.
//
// NewClient only WARNS on a host when the daemon is absent (see its comment:
// on macOS the agent runs to drive a native Metal ollama with no Docker at
// all, and on Linux dockerd may simply start later). So `s.docker != nil` has
// never meant "Docker works" on a host, and the API's nil check could not
// catch it — every start returned HTTP 200 "starting" and failed later in a
// goroutine, on a node where nothing could ever start.
//
// Live probe rather than a cached flag from construction: dockerd starting or
// stopping after the agent did is exactly the case this has to answer for.
func (c *Client) Reachable() bool {
	if c == nil || c.docker == nil {
		return false
	}
	return pingDocker(c.docker) == nil
}

// Close releases the Docker client resources.
func (c *Client) Close() error {
	return c.docker.Close()
}

// listContainers and listImages unwrap the moby/v2 client's wrapped results
// to the bare slices the pre-split github.com/docker/docker API returned.
func (c *Client) listContainers(ctx context.Context, opts client.ContainerListOptions) ([]container.Summary, error) {
	res, err := c.docker.ContainerList(ctx, opts)
	return res.Items, err
}

func (c *Client) listImages(ctx context.Context, opts client.ImageListOptions) ([]image.Summary, error) {
	res, err := c.docker.ImageList(ctx, opts)
	return res.Items, err
}

// StartBackend creates and starts a backend container using the Docker API.
// No Docker CLI needed — container config is defined in backends.go.
//
// `overrides` carries controller-supplied values that take
// precedence over the worker's local .env / spec defaults. Empty/zero
// fields fall through to the existing env-based resolution, preserving
// backwards compat for callers that don't supply overrides.
func (c *Client) StartBackend(ctx context.Context, backend, model string, gpuCount int, overrides StartOverrides) error {
	return c.StartBackendSDK(ctx, backend, model, gpuCount, overrides)
}

// StopBackend stops and removes a backend container using the Docker API.
func (c *Client) StopBackend(ctx context.Context, backend string) error {
	return c.StopBackendSDK(ctx, backend)
}

// RunningBackends returns a map of backend_type -> model for all currently
// running PAI backend containers.
func (c *Client) RunningBackends(ctx context.Context) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return map[string]string{}
	}

	backends := make(map[string]string)
	for _, ctr := range containers {
		name := strings.TrimPrefix(ctr.Names[0], "/")
		inspectRes, err := c.docker.ContainerInspect(ctx, ctr.ID, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		inspect := inspectRes.Container

		envMap := parseEnv(inspect.Config.Env)
		cmdArgs := inspect.Config.Cmd

		key := backendKeyFromName(name)
		switch key {
		case "vllm", "vllm-secondary":
			model := firstNonEmpty(envMap["MODEL_NAME"], envMap["VLLM_MODEL"])
			if model == "" {
				model = findArgValue(cmdArgs, "--model")
			}
			backends[key] = model

		case "llamacpp":
			model := envMap["MODEL_PATH"]
			if idx := strings.LastIndex(model, "/"); idx >= 0 {
				model = model[idx+1:]
			}
			backends["llamacpp"] = model

		case "airllm":
			backends["airllm"] = envMap["MODEL_PATH"]

		case "ollama":
			model := envMap["OLLAMA_MODEL"]
			if model == "" {
				model = c.queryOllamaModel(ctx)
			}
			if model == "" {
				model = "ollama"
			}
			backends["ollama"] = model

		case "embedding":
			model := envMap["MODEL_ID"]
			if model == "" {
				model = findArgValue(cmdArgs, "--model-id")
			}
			if model == "" {
				model = "tei"
			}
			backends["embedding"] = model

		case "reranker":
			// Two engines share the noo-reranker name: llamacpp reads
			// MODEL_PATH (a /models/<file>.gguf path), TEI reads MODEL_ID
			// (a HuggingFace repo id).
			model := envMap["MODEL_PATH"]
			if idx := strings.LastIndex(model, "/"); idx >= 0 {
				model = model[idx+1:]
			}
			if model == "" {
				model = envMap["MODEL_ID"]
			}
			if model == "" {
				model = findArgValue(cmdArgs, "--model-id")
			}
			backends["reranker"] = model
		}
	}

	return backends
}

// backendKeyFromName maps a running container name to its backend key,
// using the same substring heuristics as RunningBackends. Returns "" for
// containers that aren't a recognized PAI backend. Shared so RunningBackends
// and BackendLabels agree on which container is which backend.
// renameOrphan matches docker's deferred-removal name: a 12-hex prefix and
// an underscore before the original name (`a1b2c3d4e5f6_noo-llamacpp`).
// the design named the class; scripts/noo-host-watcher.sh reaps them.
var renameOrphan = regexp.MustCompile(`^[0-9a-f]{12}_`)

func backendKeyFromName(name string) string {
	// A rename-orphan is a container the agent no longer manages, left
	// behind by a deferred removal. It still CONTAINS the backend's name,
	// so a substring match counted it as the live backend — and since the
	// caller builds a map, whichever came last in the listing won. The
	// symptom is the reconciler seeing a stale model forever: it recreates
	// the backend every tick, logs "backend started", then reads the ORPHAN
	// back and decides it still does not match. Observed on host9
	// 2026-09-04, where a placement change never took effect while every
	// tick reported success.
	if renameOrphan.MatchString(name) {
		return ""
	}
	// A stunnel sidecar carries the backend's name (noo-stunnel-llamacpp,
	// noo-stunnel-ollama) and none of its env: counted as the backend it
	// fronts, it set the model to "" and — the map keeping whichever came
	// last — could make a running llama.cpp vanish from RunningBackends.
	if strings.Contains(name, "stunnel") {
		return ""
	}
	switch {
	case strings.Contains(name, "vllm"):
		if strings.Contains(name, "vllm-secondary") {
			return "vllm-secondary"
		}
		return "vllm"
	case strings.Contains(name, "llamacpp"):
		return "llamacpp"
	case strings.Contains(name, "airllm"):
		return "airllm"
	case strings.Contains(name, "ollama") && !strings.Contains(name, "embed"):
		return "ollama"
	case strings.Contains(name, "reranker"):
		// noo-reranker matches neither "llamacpp" nor "tei" regardless of
		// which engine is inside. Leaving it unmapped made RunningBackends()
		// blind to a healthy reranker: the reconciler recreated it every
		// tick (was_running=false) and the heartbeat reported it missing,
		// firing node_placement_drift forever.
		return "reranker"
	case strings.Contains(name, "tei"):
		return "embedding"
	}
	return ""
}

// BackendLabels returns backend_key -> value of the given container label
// for every running PAI backend, keyed the same way as RunningBackends.
// A running backend whose container lacks the label maps to "" (present in
// the map with an empty value) — the reconciler treats that as spec drift
// once, to adopt the label. Reads labels straight off the container-list
// summary (no per-container inspect).
func (c *Client) BackendLabels(ctx context.Context, label string) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out := map[string]string{}
	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return out
	}
	for _, ctr := range containers {
		if len(ctr.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(ctr.Names[0], "/")
		key := backendKeyFromName(name)
		if key == "" {
			continue
		}
		out[key] = ctr.Labels[label]
	}
	return out
}

// FloatingBackendImages is, per running backend container, the ref it was
// created from when that ref can move under it — the heartbeat's
// `image_floating` judgement (imageFacts). A current agent refuses to create
// such a container, so one running is a leftover from an older agent; the
// reconciler recreates it from the pinned ref once, like a spec drift.
func (c *Client) FloatingBackendImages(ctx context.Context) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out := map[string]string{}
	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return out
	}
	for _, ctr := range containers {
		if len(ctr.Names) == 0 {
			continue
		}
		key := backendKeyFromName(strings.TrimPrefix(ctr.Names[0], "/"))
		if key == "" {
			continue
		}
		if img, floating := imageFacts(ctr.Image); floating {
			out[key] = img
		}
	}
	return out
}

// ContainerNames returns the names of all running containers.
func (c *Client) ContainerNames(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil
	}

	names := make([]string, 0, len(containers))
	for _, ctr := range containers {
		name := strings.TrimPrefix(ctr.Names[0], "/")
		names = append(names, name)
	}
	return names
}

// ContainerInfo holds basic container metadata for listing.
type ContainerInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Image  string `json:"image"`
}

// ListContainers returns info about all containers (including stopped).
func (c *Client) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	containers, err := c.listContainers(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}

	infos := make([]ContainerInfo, 0, len(containers))
	for _, ctr := range containers {
		name := strings.TrimPrefix(ctr.Names[0], "/")
		infos = append(infos, ContainerInfo{
			ID:     ctr.ID[:12],
			Name:   name,
			Status: string(ctr.State),
			Image:  ctr.Image,
		})
	}
	return infos, nil
}

// ContainerLogs retrieves logs from a container.
// logReadBudget caps how much of a container's log stream one fetch will
// read. The tail is also capped at 2000 lines; this is the byte-side twin,
// so a container emitting very long lines cannot make one log request hold
// an unbounded buffer.
const logReadBudget = 8 << 20 // 8 MiB

func (c *Client) ContainerLogs(ctx context.Context, containerName string, tail int, since string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if tail > 2000 {
		tail = 2000
	}

	opts := client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", tail),
		Timestamps: true,
	}
	if since != "" {
		opts.Since = since
	}

	// Whether the stream is framed depends on the container's TTY, and
	// guessing is what broke this before. Ask.
	tty := false
	if ins, err := c.docker.ContainerInspect(ctx, containerName, client.ContainerInspectOptions{}); err == nil {
		if cfg := ins.Container.Config; cfg != nil {
			tty = cfg.Tty
		}
	}

	reader, err := c.docker.ContainerLogs(ctx, containerName, opts)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	lines, err := logLinesFromStream(reader, tty, tail)
	if err != nil {
		return nil, fmt.Errorf("read logs for %s: %w", containerName, err)
	}
	return lines, nil
}

// logLinesFromStream turns one container log stream into its last `tail`
// lines. Split out from ContainerLogs because both bugs it fixes lived
// here and neither was reachable by a test while it needed a live daemon.
//
// ONE Read used to be the whole implementation, into a 512 KiB buffer:
//
//	buf := make([]byte, 512*1024)
//	n, _ := reader.Read(buf)
//
// io.Reader makes no promise to fill a buffer — it returns what happens to
// be available — so the number of lines that came back had nothing to do
// with `tail`. Live on 2026-09-12: asking for 400 lines returned 5, asking
// for 60 returned 20, and asking for 1000 with a filter returned nothing at
// all, which reads as "no matches" rather than "truncated fetch" and sent a
// log investigation down the wrong path.
//
// The framing was the second bug. A non-TTY container's stream carries an
// 8-byte header per FRAME, not per line, whose 4-byte big-endian length can
// itself contain a newline. Splitting on "\n" and then trimming any line
// whose first byte is <= 2 therefore both missed real headers and ate real
// content. stdcopy is the demuxer for this, and the sibling MCP stdio path
// in this same package already uses it.
func logLinesFromStream(r io.Reader, tty bool, tail int) ([]string, error) {
	var out strings.Builder
	limited := io.LimitReader(r, logReadBudget)
	if tty {
		// A TTY container's log stream is raw bytes, no frames.
		if _, err := io.Copy(&out, limited); err != nil {
			return nil, err
		}
	} else if _, err := stdcopy.StdCopy(&out, &out, limited); err != nil {
		return nil, err
	}

	text := strings.TrimRight(out.String(), "\n")
	if text == "" {
		return []string{}, nil
	}
	lines := strings.Split(text, "\n")
	// `tail` is advisory to the daemon and the budget above can clip the
	// head of the stream, so keep the LAST tail lines: a tail that returns
	// the oldest lines it managed to read is worse than useless.
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	return lines, nil
}

// StopAllPAIContainers stops and removes all PAI containers except the node-agent itself.
// Returns the count of containers stopped.
func (c *Client) StopAllPAIContainers(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	containers, err := c.listContainers(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return 0, err
	}

	stopped := 0
	timeout := 10
	for _, ctr := range containers {
		name := strings.TrimPrefix(ctr.Names[0], "/")
		if !strings.HasPrefix(name, "noo-") || name == "noo-node-agent" {
			continue
		}
		_, _ = c.docker.ContainerStop(ctx, ctr.ID, client.ContainerStopOptions{Timeout: &timeout})
		_, _ = c.docker.ContainerRemove(ctx, ctr.ID, client.ContainerRemoveOptions{})
		stopped++
	}
	return stopped, nil
}

// IsStackImageTag reports whether an image tag belongs to this deployment.
//
// Two shapes, because the stack has two kinds of image:
//
//   - `<NOO_IMAGE_PREFIX>/<name>:<tag>` — the composed services. The prefix is
//     a DEPLOYMENT variable (`ghcr.io/personifai` on a --dist install), and
//     defaults to the local build name when the node was never told.
//   - `noo-<name>:<tag>` — images built with no prefix at all
//     (noo-sandbox-base, noo-browser).
//
// This used to be a bare `pai-assistant/` prefix check. The rename campaign
// updated the CONTAINER half of clean to `noo-` and left this one behind, so
// on every node whose images are named anything else — which is every --dist
// install, and every locally-built noo- image — it matched nothing and
// reported `images_removed: 0`. Zero reads as "nothing to remove", not as
// "I looked in the wrong place".
func IsStackImageTag(tag string) bool {
	if strings.HasPrefix(tag, "noo-") {
		return true
	}
	prefix := os.Getenv("NOO_IMAGE_PREFIX")
	if prefix == "" {
		// The local build name, which is what compose falls back to.
		prefix = "pai-assistant"
	}
	return strings.HasPrefix(tag, prefix+"/")
}

// RemoveStackImages removes the images this deployment built or pulled for
// itself. Returns the count removed.
//
// Only reached for a DEEP clean: the images are the expensive half to get
// back (a multi-GB pull or a rebuild), so removing them is opt-in.
func (c *Client) RemoveStackImages(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	images, err := c.listImages(ctx, client.ImageListOptions{})
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, img := range images {
		for _, tag := range img.RepoTags {
			if IsStackImageTag(tag) {
				_, _ = c.docker.ImageRemove(ctx, img.ID, client.ImageRemoveOptions{Force: true})
				removed++
				break
			}
		}
	}
	return removed, nil
}

// PullProfile pulls the Docker image for a backend.
// The profile name maps to a backend spec whose image we pull.
func (c *Client) PullProfile(ctx context.Context, profile string) error {
	spec, ok := backendSpecs[profile]
	if !ok {
		return fmt.Errorf("unknown profile: %s", profile)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// Over the artifact rail like every other start path (image_source.go);
	// the profile's image may carry ${VAR:-default}, which a pull of the
	// raw string never resolved.
	img := resolveEnv(spec.Image)
	if err := ensureImageFn(ctx, c, img); err != nil {
		return fmt.Errorf("pull %s: %w", img, err)
	}
	return nil
}

// helpers

func parseEnv(envList []string) map[string]string {
	m := make(map[string]string, len(envList))
	for _, e := range envList {
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			m[e[:idx]] = e[idx+1:]
		}
	}
	return m
}

func findArgValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func (c *Client) queryOllamaModel(ctx context.Context) string {
	if c.httpClient == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s://ollama:11434/api/ps", c.scheme)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := c.httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	// Simple JSON extraction without importing encoding/json for this small case
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	// Look for "name": "..." in the models array
	if idx := strings.Index(body, `"name"`); idx >= 0 {
		rest := body[idx:]
		if start := strings.IndexByte(rest, ':'); start >= 0 {
			rest = strings.TrimSpace(rest[start+1:])
			rest = strings.TrimPrefix(rest, `"`)
			if end := strings.IndexByte(rest, '"'); end >= 0 {
				return rest[:end]
			}
		}
	}
	return ""
}
