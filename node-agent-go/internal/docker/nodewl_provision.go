// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlenv"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelsets"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// Provisioning an add-on's node workload (i300 F5a). The node agent loads the
// workload's image from the rail, creates the door sidecar and the worker
// container STOPPED, and leaves them there: start, stop, release, drain, the
// heartbeat rows, the consent policy and the proxy route are F5b's, and reach
// this file only through Provision, Deprovision, Status and DoorAddr.
//
// Provisioned means: image present at exactly image.id, every set verified,
// the private network, the sidecar and the worker created and not started.
// The contract is docs/reference/node-workloads.md.

// ErrSetsPending: a set the workload needs is still being fetched. It is not
// a refusal (no reason is reported); the caller asks again after the fetch.
var ErrSetsPending = errors.New("a model set is still being fetched")

// ErrWorkerRunning: the pair on the node differs from the entry and the worker
// is running. A provision never cuts a live session; the caller drains and
// stops it (F5b), then provisions again.
var ErrWorkerRunning = errors.New("the worker is running; drain and stop it before it is recreated")

// SetSource is the model-set store as the provisioner sees it
// (modelsets.Store).
type SetSource interface {
	State(ref modelsets.Ref) modelsets.Status
	Dir(ref modelsets.Ref) string
}

// WorkloadStatus is what Status reports for one (add-on, workload).
type WorkloadStatus struct {
	// Known: Provision has run for it in this process.
	Known bool
	// Provisioned: the pair exists on the node as the last Provision left it.
	Provisioned bool
	// Reason is a nodewl.Reason* code when the last Provision was refused,
	// else "".
	Reason string
	// Detail is the human text behind Reason (or behind an infrastructure
	// failure, which carries no reason). Never shown as a reason.
	Detail string
	// Pending: the last Provision is waiting on a set fetch.
	Pending  bool
	DoorPort int
}

// ctrInfo and netInfo are what the provisioner needs to know about what is
// on the node.
type ctrInfo struct {
	ID      string
	Labels  map[string]string
	Running bool
	// Status is docker's own word: created (never started), running, exited,
	// dead... F5b reads "created" as "not yet started" and "exited" as "ran
	// and stopped".
	Status    string
	StartedAt time.Time         // zero when it never started
	IPs       map[string]string // network name -> address
}

type netInfo struct {
	Internal bool
	Labels   map[string]string
}

// provAPI is the daemon, as narrow as the provisioner uses it: the seam the
// tests fake. dockerProvAPI is the real one.
type provAPI interface {
	ImageExists(ctx context.Context, id string) (bool, error)
	// LoadImage loads a tar and returns the ID of every image it produced.
	LoadImage(ctx context.Context, tar *os.File) ([]string, error)
	InspectContainer(ctx context.Context, name string) (*ctrInfo, error) // nil when absent
	CreateContainer(ctx context.Context, s createSpec) error
	StartContainer(ctx context.Context, name string) error
	StopContainer(ctx context.Context, name string, graceS int) error
	RemoveContainer(ctx context.Context, name string) error
	InspectNetwork(ctx context.Context, name string) (*netInfo, error) // nil when absent
	CreateInternalNetwork(ctx context.Context, name string, labels map[string]string) error
	RemoveNetwork(ctx context.Context, name string) error
	RemoveVolumes(ctx context.Context, addon, workload string) error
	NvidiaRuntime(ctx context.Context) bool
}

// NodeWorkloads provisions node workloads. Build one with NewNodeWorkloads;
// every field below it is a seam a test replaces.
type NodeWorkloads struct {
	// Sets is the model-set store.
	Sets SetSource
	// PKIDir is the node's PKI directory (the cluster CA and the door leaves).
	PKIDir func() string
	// AgentUID is the uid this agent runs as.
	AgentUID func() int
	// GPUDevices returns the devices a workload with accel.gpu > 0 is pinned
	// to. nil, or an error-free empty answer, means "no lease yet": the
	// workload is pinned to GPU indices 0..gpu-1 (F5b supplies the lease).
	GPUDevices func(e nodewl.Entry) ([]string, error)

	api          provAPI
	goos, arch   string
	fetchTar     func(ctx context.Context, artifact string) (path string, cleanup func(), err error)
	doorImage    func(ctx context.Context) (string, error)
	doorSelfName func() (string, error)

	mu     sync.Mutex
	status map[string]WorkloadStatus
	locks  sync.Map // addon/name -> *sync.Mutex

	lc lifeCycle // F5b: nodewl_lifecycle.go
}

// SetAdmit installs the node's gate (consent and the placement-side
// refusals). Without one every entry is refused as consent_none.
func (p *NodeWorkloads) SetAdmit(f func(ctx context.Context, e nodewl.Entry) error) { p.lc.Admit = f }

// NewNodeWorkloads is the production provisioner over c.
func NewNodeWorkloads(c *Client, sets SetSource) *NodeWorkloads {
	return &NodeWorkloads{
		Sets:     sets,
		PKIDir:   ctrlenv.PKIDir,
		AgentUID: os.Getuid,
		api:      dockerProvAPI{c},
		goos:     runtime.GOOS,
		arch:     runtime.GOARCH,
		fetchTar: fetchRailTar,
		doorImage: func(ctx context.Context) (string, error) {
			return c.ensureSidecarImage(ctx, "")
		},
		doorSelfName: doorSelfName,
		status:       map[string]WorkloadStatus{},
		lc:           lifeCycle{doorCall: newDoorCaller()},
	}
}

func wlKey(addon, name string) string { return addon + "/" + name }

func (p *NodeWorkloads) lock(addon, name string) func() {
	m, _ := p.locks.LoadOrStore(wlKey(addon, name), &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func refuse(code, inner, format string, a ...any) error {
	return &nodewl.Error{Code: code, Inner: inner, Detail: fmt.Sprintf(format, a...)}
}

func (p *NodeWorkloads) record(e nodewl.Entry, provisioned bool, err error) {
	st := WorkloadStatus{Known: true, Provisioned: provisioned, DoorPort: WorkloadDoorPort}
	switch {
	case err == nil:
	case errors.Is(err, ErrSetsPending):
		st.Pending, st.Detail = true, err.Error()
	default:
		st.Reason, st.Detail = nodewl.CodeOf(err), err.Error()
	}
	p.mu.Lock()
	p.status[wlKey(e.Addon, e.Name)] = st
	p.mu.Unlock()
}

// Status is what the last Provision of addon/name left. A refusal keeps the
// last good state (Provisioned) and adds the reason: a refusal never changes
// a container.
func (p *NodeWorkloads) Status(addon, name string) WorkloadStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status[wlKey(addon, name)]
}

// Provision makes the entry's workload provisioned: image loaded, sets
// verified, the private network, the door and the worker created and not
// started. It is idempotent (a pair that already matches is left alone) and
// a changed spec recreates both, still stopped. The error is a
// *nodewl.Error carrying the reason (nodewl.CodeOf), ErrSetsPending,
// ErrWorkerRunning, or an infrastructure error with no reason.
func (p *NodeWorkloads) Provision(ctx context.Context, e nodewl.Entry) error {
	defer p.lock(e.Addon, e.Name)()
	prev := p.Status(e.Addon, e.Name)
	touched, err := p.provision(ctx, e)
	switch {
	case err == nil:
		p.record(e, true, nil)
	case touched:
		p.record(e, false, err)
	default:
		p.record(e, prev.Provisioned, err)
	}
	if err != nil {
		slog.Warn("node workload: not provisioned", "addon", e.Addon, "workload", e.Name,
			"reason", nodewl.CodeOf(err), "inner", innerOf(err), "error", err)
	}
	return err
}

func innerOf(err error) string {
	var ne *nodewl.Error
	if errors.As(err, &ne) {
		return ne.Inner
	}
	return ""
}

// provision returns touched=true once it has changed a container, so Status
// stops reporting the old good state.
func (p *NodeWorkloads) provision(ctx context.Context, e nodewl.Entry) (touched bool, err error) {
	d := e.Decl
	if p.goos != "linux" {
		return false, refuse(nodewl.ReasonDoorUnreachable, "", "the door is reached over an internal bridge network, which this host (%s) cannot route to", p.goos)
	}
	if e.Door == nil || len(e.Door.Admit) != 1 {
		return false, refuse(nodewl.ReasonAdmitInvalid, "", "door.admit must be exactly this node's agent")
	}
	admit, perr := checkDoorPin(e.Door.Admit[0])
	if perr != nil {
		return false, refuse(nodewl.ReasonAdmitInvalid, "", "%v", perr)
	}
	// admit[0] was already held to this node's agent CN by ParseDesired; read
	// the leaf again so an entry that did not come from it is held to it too.
	// A leaf that cannot be read is not a verdict (the door cannot be pinned
	// to a name nobody can confirm, but ParseDesired's check stands).
	if p.doorSelfName != nil {
		if want, serr := p.doorSelfName(); serr == nil && want != admit {
			return false, refuse(nodewl.ReasonAdmitInvalid, "", "door.admit %q is not this node's agent %q", admit, want)
		}
	}
	if d.UID == 0 {
		return false, refuse(nodewl.ReasonDeclInvalid, nodewl.CodeUIDInvalid, "uid 0")
	}
	if d.UID == int64(p.AgentUID()) {
		return false, refuse(nodewl.ReasonDeclInvalid, "uid_is_agent", "uid %d is the uid this agent runs as", d.UID)
	}
	if err := nodewl.CheckEnv(e); err != nil {
		return false, err
	}
	if a := artifactArch(e.Image.Artifact); a != p.arch {
		return false, refuse(nodewl.ReasonArchMismatch, "", "image.artifact is built for %q, this node is %q", a, p.arch)
	}

	// Whatever already carries our names must be ours.
	workerName, doorName, netName := WorkloadContainerName(e.Addon, e.Name), WorkloadDoorName(e.Addon, e.Name), WorkloadNetworkName(e.Addon, e.Name)
	oldW, err := p.api.InspectContainer(ctx, workerName)
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", workerName, err)
	}
	oldD, err := p.api.InspectContainer(ctx, doorName)
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", doorName, err)
	}
	oldN, err := p.api.InspectNetwork(ctx, netName)
	if err != nil {
		return false, fmt.Errorf("inspect network %s: %w", netName, err)
	}
	for _, c := range []struct {
		name   string
		labels map[string]string
		there  bool
	}{
		{workerName, labelsOf(oldW), oldW != nil},
		{doorName, labelsOf(oldD), oldD != nil},
		{netName, netLabels(oldN), oldN != nil},
	} {
		if c.there && c.labels[LabelManagedBy] != ManagedByAgent {
			return false, refuse(nodewl.ReasonContainerConflict, "", "%s exists and was not created by this agent", c.name)
		}
	}

	leaf, err := p.checkLeaf(e)
	if err != nil {
		return false, err
	}
	mounts, slots, err := p.resolveSets(e)
	if err != nil {
		return false, err
	}
	var devices []string
	leased := false
	if d.Accel.GPU > 0 {
		if !p.api.NvidiaRuntime(ctx) {
			return false, refuse(nodewl.ReasonNvidiaRuntimeMissing, "", "the nvidia container runtime is not registered with docker")
		}
		devices, leased, err = p.gpuDevices(e)
		if err != nil {
			return false, err
		}
	}
	// Every refusal that needs no image comes before the (large) image fetch.
	if _, err := workerEnv(specInput{Entry: e, Slots: slots, GPUDevices: devices}); err != nil {
		return false, err
	}
	if err := p.ensureImage(ctx, e); err != nil {
		return false, err
	}
	doorImg, err := p.doorImage(ctx)
	if err != nil {
		return false, fmt.Errorf("door image: %w", err)
	}

	specs, err := buildWorkloadSpecs(specInput{
		Entry: e, WorkerImage: e.Image.ID, DoorImage: doorImg, AdmitCN: admit,
		CAPath: leaf.ca, LeafCrt: leaf.crt, LeafKey: leaf.key, LeafPrint: leaf.print,
		Sets: mounts, Slots: slots, GPUDevices: devices, GPULeased: leased,
	})
	if err != nil {
		return false, err
	}

	// A pair that already is this spec, stopped or not, is left alone.
	if oldW != nil && oldD != nil && oldN != nil && oldN.Internal &&
		oldW.Labels[SpecHashLabel] == specs.Hash && oldD.Labels[SpecHashLabel] == specs.Hash {
		return false, nil
	}
	if (oldW != nil && oldW.Running) || (oldD != nil && oldD.Running) {
		return false, ErrWorkerRunning
	}

	touched = true
	if err := p.teardown(ctx, e.Addon, e.Name); err != nil {
		return touched, err
	}
	if err := p.api.CreateInternalNetwork(ctx, netName, map[string]string{
		LabelManagedBy: ManagedByAgent, LabelAddon: e.Addon, LabelWorkload: e.Name,
	}); err != nil {
		return touched, fmt.Errorf("create network %s: %w", netName, err)
	}
	if err := p.api.CreateContainer(ctx, specs.Door); err != nil {
		_ = p.teardown(ctx, e.Addon, e.Name)
		return touched, fmt.Errorf("create %s: %w", doorName, err)
	}
	if err := p.api.CreateContainer(ctx, specs.Worker); err != nil {
		_ = p.teardown(ctx, e.Addon, e.Name)
		return touched, fmt.Errorf("create %s: %w", workerName, err)
	}
	slog.Info("node workload provisioned", "addon", e.Addon, "workload", e.Name, "worker", workerName,
		"door", doorName, "network", netName, "spec", specs.Hash[:12], "image", shortImageID(e.Image.ID))
	return touched, nil
}

func labelsOf(c *ctrInfo) map[string]string {
	if c == nil {
		return nil
	}
	return c.Labels
}

func netLabels(n *netInfo) map[string]string {
	if n == nil {
		return nil
	}
	return n.Labels
}

// Deprovision removes the worker, the door, the private network and the
// scratch volumes of addon/name. It removes only what this agent created: a
// container of that name without noo.managed-by=agent is left alone and
// reported as container_conflict. Removing what is absent is not an error.
func (p *NodeWorkloads) Deprovision(ctx context.Context, addon, name string) error {
	defer p.lock(addon, name)()
	for _, n := range []string{WorkloadContainerName(addon, name), WorkloadDoorName(addon, name)} {
		c, err := p.api.InspectContainer(ctx, n)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", n, err)
		}
		if c != nil && c.Labels[LabelManagedBy] != ManagedByAgent {
			return refuse(nodewl.ReasonContainerConflict, "", "%s exists and was not created by this agent", n)
		}
	}
	if err := p.teardown(ctx, addon, name); err != nil {
		return err
	}
	p.mu.Lock()
	delete(p.status, wlKey(addon, name))
	p.mu.Unlock()
	return nil
}

// teardown removes the pair, the volumes and the network, worker first.
func (p *NodeWorkloads) teardown(ctx context.Context, addon, name string) error {
	for _, n := range []string{WorkloadContainerName(addon, name), WorkloadDoorName(addon, name)} {
		if err := p.api.RemoveContainer(ctx, n); err != nil {
			return fmt.Errorf("remove %s: %w", n, err)
		}
	}
	if err := p.api.RemoveVolumes(ctx, addon, name); err != nil {
		return fmt.Errorf("remove scratch volumes: %w", err)
	}
	if err := p.api.RemoveNetwork(ctx, WorkloadNetworkName(addon, name)); err != nil {
		return fmt.Errorf("remove network: %w", err)
	}
	return nil
}

// DoorAddr is host:port the agent dials the door on. The address is the
// door's on the workload's private network and changes whenever the door is
// recreated, so it is read from the daemon every time and never cached.
func (p *NodeWorkloads) DoorAddr(ctx context.Context, addon, name string) (string, error) {
	c, err := p.api.InspectContainer(ctx, WorkloadDoorName(addon, name))
	if err != nil {
		return "", err
	}
	if c == nil || c.Labels[LabelManagedBy] != ManagedByAgent {
		return "", fmt.Errorf("no door container for %s/%s", addon, name)
	}
	ip := c.IPs[WorkloadNetworkName(addon, name)]
	if ip == "" {
		return "", fmt.Errorf("the door of %s/%s has no address on %s (is it running?)", addon, name, WorkloadNetworkName(addon, name))
	}
	return ip + ":" + strconv.Itoa(WorkloadDoorPort), nil
}

// artifactArch is the <arch> of noo-addon-wl_<...>_<arch>.tar.
func artifactArch(artifact string) string {
	s := strings.TrimSuffix(artifact, ".tar")
	return s[strings.LastIndex(s, "_")+1:]
}

type leafFiles struct{ ca, crt, key, print string }

// checkLeaf finds the door leaf the CLI issued for this node
// (svc-addon-<addon>-<workload>.{crt,key} in the PKI directory) and the
// cluster CA, and checks the certificate names the door. Anything missing is
// door_leaf_missing and nothing is provisioned.
func (p *NodeWorkloads) checkLeaf(e nodewl.Entry) (leafFiles, error) {
	fix := "re-provision (`noo upgrade --nodes`)"
	dir := p.PKIDir()
	if dir == "" {
		return leafFiles{}, refuse(nodewl.ReasonDoorLeafMissing, "", "the node's PKI directory is not set; %s", fix)
	}
	lf := leafFiles{
		ca:  filepath.Join(dir, "ca.crt"),
		crt: filepath.Join(dir, e.Door.Leaf+".crt"),
		key: filepath.Join(dir, e.Door.Leaf+".key"),
	}
	for _, f := range []string{lf.ca, lf.crt, lf.key} {
		if fi, err := os.Stat(f); err != nil || !fi.Mode().IsRegular() {
			return leafFiles{}, refuse(nodewl.ReasonDoorLeafMissing, "", "%s is not there; %s", f, fix)
		}
	}
	names, err := leafDNSNames(lf.crt)
	if err != nil {
		return leafFiles{}, refuse(nodewl.ReasonDoorLeafMissing, "", "%s is not a readable certificate (%v); %s", lf.crt, err, fix)
	}
	want := WorkloadDoorName(e.Addon, e.Name)
	found := false
	for _, n := range names {
		found = found || n == want
	}
	if !found {
		return leafFiles{}, refuse(nodewl.ReasonDoorLeafMissing, "", "%s does not name %s; %s", lf.crt, want, fix)
	}
	raw, err := os.ReadFile(lf.crt)
	if err != nil {
		return leafFiles{}, refuse(nodewl.ReasonDoorLeafMissing, "", "%s: %v; %s", lf.crt, err, fix)
	}
	sum := sha256.Sum256(raw)
	lf.print = hex.EncodeToString(sum[:])
	return lf, nil
}

// resolveSets turns the entry's sets into read-only mounts, refusing unless
// every one is verified on this node.
func (p *NodeWorkloads) resolveSets(e nodewl.Entry) ([]setMount, []slotVars, error) {
	var mounts []setMount
	var slots []slotVars
	pending := false
	for _, s := range e.Decl.Models {
		refs := e.Sets[s.Slot]
		if len(refs) == 0 {
			if s.Optional {
				continue
			}
			return nil, nil, refuse(nodewl.ReasonSetMissing, "", "slot %q has no set", s.Slot)
		}
		sv := slotVars{Slot: s.Slot}
		for _, r := range refs {
			ref := modelsets.Ref{ID: r.ID, Revision: r.Revision}
			if !nodewl.ValidSetRef(r.ID, r.Revision) {
				return nil, nil, refuse(nodewl.ReasonSetSlotInvalid, "", "slot %q: malformed set %s", s.Slot, ref)
			}
			switch st := p.Sets.State(ref); st.State {
			case modelsets.StateVerified:
			case modelsets.StateFetching:
				pending = true
				continue
			case modelsets.StateRefused:
				return nil, nil, refuse(nodewl.ReasonSetUnverified, "", "set %s is refused (%s)", ref, st.Reason)
			default:
				return nil, nil, refuse(nodewl.ReasonSetMissing, "", "set %s is not on this node", ref)
			}
			target := s.Target
			if s.Many {
				target = s.Target + "/" + r.ID
			}
			mounts = append(mounts, setMount{Source: p.Sets.Dir(ref), Target: target})
			sv.IDs = append(sv.IDs, r.ID)
			sv.Revs = append(sv.Revs, r.Revision)
		}
		slots = append(slots, sv)
	}
	if pending {
		return nil, nil, ErrSetsPending
	}
	return mounts, slots, nil
}

// gpuDevices is the pin. The lease (F5b) will supply real devices through
// GPUDevices; until then a workload is pinned to GPU indices 0..gpu-1, which
// is exactly what Docker's own Count request selects, written down so
// NVIDIA_VISIBLE_DEVICES states it.
func (p *NodeWorkloads) gpuDevices(e nodewl.Entry) (devices []string, leased bool, err error) {
	if p.GPUDevices != nil {
		devices, err = p.GPUDevices(e)
		if err != nil {
			return nil, false, fmt.Errorf("gpu lease: %w", err)
		}
		if len(devices) > 0 {
			if int64(len(devices)) != e.Decl.Accel.GPU {
				return nil, false, fmt.Errorf("gpu lease holds %d devices, the workload wants %d", len(devices), e.Decl.Accel.GPU)
			}
			return devices, true, nil
		}
	}
	for i := int64(0); i < e.Decl.Accel.GPU; i++ {
		devices = append(devices, strconv.FormatInt(i, 10))
	}
	return devices, false, nil
}

// ensureImage makes image.id present on the node: nothing to do if an image
// of exactly that ID is there; else the tar comes over the rail (checked
// against the rail manifest's sha256), must hold one image, and loads as
// exactly one image whose ID is image.id.
func (p *NodeWorkloads) ensureImage(ctx context.Context, e nodewl.Entry) error {
	ok, err := p.api.ImageExists(ctx, e.Image.ID)
	if err != nil {
		return fmt.Errorf("inspect image %s: %w", shortImageID(e.Image.ID), err)
	}
	if ok {
		return nil
	}
	path, cleanup, err := p.fetchTar(ctx, e.Image.Artifact)
	if err != nil {
		switch {
		case errors.Is(err, ErrArtifactAbsent):
			return refuse(nodewl.ReasonImageMissing, "", "%s is not on the rail", e.Image.Artifact)
		case IsImageVerification(err):
			return refuse(nodewl.ReasonImageDigestMismatch, "", "%v", err)
		}
		return fmt.Errorf("fetch %s: %w", e.Image.Artifact, err)
	}
	defer cleanup()
	if err := checkTarOneImage(path); err != nil {
		return refuse(nodewl.ReasonImageDigestMismatch, "", "%v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open staged tar: %w", err)
	}
	defer f.Close()
	loaded, err := p.api.LoadImage(ctx, f)
	if err != nil {
		return fmt.Errorf("docker load: %w", err)
	}
	distinct := map[string]bool{}
	for _, id := range loaded {
		distinct[strings.TrimPrefix(strings.ToLower(id), "sha256:")] = true
	}
	if len(distinct) != 1 {
		return refuse(nodewl.ReasonImageDigestMismatch, "", "the tar loaded as %d images, want exactly one", len(distinct))
	}
	if !sameImageID(loaded[0], e.Image.ID) {
		return refuse(nodewl.ReasonImageDigestMismatch, "", "the tar loaded as %s, want %s", shortImageID(loaded[0]), shortImageID(e.Image.ID))
	}
	return nil
}
