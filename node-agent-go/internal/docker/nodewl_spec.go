// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// The container specs of a node workload (i300 F5a): pure functions from an
// entry and the facts the provisioner gathered to the two create calls. No
// daemon is touched here, so every property of the contract's security table
// (docs/reference/node-workloads.md, "The worker container") is pinned by a
// golden test on these structs.

// WorkloadDoorPort is the port the door accepts on, inside the sidecar's
// network namespace, on the sidecar's address on the workload's private
// network. The agent picks it (the contract: "the agent picks door_port and
// reports it"): one fixed port is enough because every workload has a
// namespace of its own, and a fixed one survives a recreate, which a random
// one would not. Reported as `door_port` in the heartbeat row.
const WorkloadDoorPort = 8443

// Labels on every container the provisioner creates. noo.addon and
// noo.workload are the pair internal/addonwl's actuator selects on; the value
// of noo.managed-by is "agent", deliberately not the "node-agent-go" the
// backend path writes, so no backend sweep claims a workload's container.
const (
	LabelManagedBy   = "noo.managed-by"
	ManagedByAgent   = "agent"
	LabelRole        = "noo.role"
	LabelReservation = "noo.reservation"
	RoleDoor         = "door"
	RoleWorker       = "worker"

	// The worker container's drain config, so a workload that desired-config
	// no longer lists (an orphan) can still be drained, even after an agent
	// restart.
	LabelDrainPath    = "noo.drain-path"
	LabelDrainDone    = "noo.drain-done-path"
	LabelDrainTimeout = "noo.drain-timeout-secs"
)

// Resource floor of the door sidecar. stunnel is tiny; the numbers only stop a
// runaway door from taking the node down.
const (
	doorMemoryBytes = 128 << 20
	doorPids        = 64
)

// Where the sidecar sees its inputs. The leaf lives here and nowhere else.
const (
	doorLeafDir = "/tls/leaf"
	doorCAPath  = "/tls/ca.crt"
)

// WorkloadContainerName is the worker's container name.
func WorkloadContainerName(addon, workload string) string { return "noo-wl-" + addon + "-" + workload }

// WorkloadDoorName is the sidecar's container name, and the DNS SAN of the
// door leaf: noo-stunnel-<addon>-<workload>.
func WorkloadDoorName(addon, workload string) string {
	return StunnelContainerPrefix + addon + "-" + workload
}

// WorkloadNetworkName is the workload's private, internal network.
func WorkloadNetworkName(addon, workload string) string { return "noo-wl-" + addon + "-" + workload }

// maxScratchEntries is the validator's cap on scratch[] (nodewl: "at most 4");
// release walks every possible volume name up to it.
const maxScratchEntries = 4

func workloadVolumeName(addon, workload string, i int) string {
	return "noo-wl-" + addon + "-" + workload + "-scratch" + strconv.Itoa(i)
}

// setMount is one verified set to bind read-only.
type setMount struct {
	Source string // the set's directory on the node
	Target string // inside the worker
}

// slotVars are the `<ADDON>_MODEL_<SLOT>_ID` and `_REVISION` values of one
// slot. A many slot lists its sets comma-separated, in placement order.
type slotVars struct {
	Slot      string
	IDs, Revs []string
}

type specInput struct {
	Entry       nodewl.Entry
	WorkerImage string // image.id, never a tag
	DoorImage   string
	AdmitCN     string // the one name the door admits (door.admit[0])
	CAPath      string // host path of the cluster CA certificate
	LeafCrt     string // host paths of the door leaf
	LeafKey     string
	LeafPrint   string // fingerprint of the leaf, so a re-issued leaf recreates the pair
	Sets        []setMount
	Slots       []slotVars
	GPUDevices  []string // the pinned devices; empty when accel.gpu is 0
	GPULeased   bool     // true when GPUDevices came from a lease, not the default
}

// createSpec is one container create call.
type createSpec struct {
	Name   string
	Config *container.Config
	Host   *container.HostConfig
	Net    *network.NetworkingConfig
}

// workloadSpecs is both create calls plus the hash that identifies them.
type workloadSpecs struct {
	Door, Worker createSpec
	Network      string
	Hash         string
}

func upperEnvName(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
}

// slotEnvNames are the two variables that tell the worker which set is in a
// slot: <ADDON_UPPER>_MODEL_<SLOT_UPPER>_ID and _REVISION.
func slotEnvNames(addon, slot string) (id, rev string) {
	base := nodewl.EnvPrefix(addon) + "MODEL_" + upperEnvName(slot)
	return base + "_ID", base + "_REVISION"
}

// workerEnv is the whole environment of the worker, sorted: the placement's
// declared keys (values already held to the decl's bounds), the slot
// variables, the offline switches and, for a GPU workload, the NVIDIA ones.
// Nothing else is ever added. A declared key that collides with a variable
// the agent sets is refused rather than overridden.
func workerEnv(in specInput) ([]string, error) {
	e := in.Entry
	env := map[string]string{}
	for k, v := range e.Env {
		env[k] = v
	}
	set := func(k, v string) error {
		if _, taken := env[k]; taken {
			return &nodewl.Error{Code: nodewl.ReasonEnvOutOfBounds, Detail: fmt.Sprintf("env %s is set by the agent and may not be declared", k)}
		}
		env[k] = v
		return nil
	}
	for _, s := range in.Slots {
		idK, revK := slotEnvNames(e.Addon, s.Slot)
		if err := set(idK, strings.Join(s.IDs, ",")); err != nil {
			return nil, err
		}
		if err := set(revK, strings.Join(s.Revs, ",")); err != nil {
			return nil, err
		}
	}
	env["HF_HUB_OFFLINE"] = "1"
	env["TRANSFORMERS_OFFLINE"] = "1"
	if e.Decl.Accel.GPU > 0 {
		env["NVIDIA_DRIVER_CAPABILITIES"] = "compute,utility"
		env["NVIDIA_VISIBLE_DEVICES"] = strings.Join(in.GPUDevices, ",")
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out, nil
}

func baseLabels(e nodewl.Entry, role string) map[string]string {
	l := map[string]string{
		LabelAddon:     e.Addon,
		LabelWorkload:  e.Name,
		LabelManagedBy: ManagedByAgent,
		LabelRole:      role,
	}
	if e.Reservation != nil && *e.Reservation != "" {
		l[LabelReservation] = *e.Reservation
	}
	return l
}

// workerLabels are the worker container's labels: the base ones and its drain
// config (read back for an orphan, see NodeWorkloads.ReleaseOrphans).
func workerLabels(e nodewl.Entry) map[string]string {
	l := baseLabels(e, RoleWorker)
	l[LabelDrainPath] = e.Drain.Path
	l[LabelDrainDone] = e.Drain.DonePath
	l[LabelDrainTimeout] = strconv.FormatInt(e.Drain.TimeoutSecs, 10)
	return l
}

// scratchMounts are the writable places a worker has: the mounts, and the
// HostConfig.Tmpfs entries. A tmpfs_mb entry is a tmpfs of that size, given
// as HostConfig.Tmpfs's option string ("rw,nosuid,nodev,noexec,size=<n>m,
// mode=1777"), the form rootFloor gives every door's /tmp: the Mounts API's
// TmpfsOptions.Options accepts only exec/noexec and a real daemon refuses
// nosuid and nodev there ("invalid mount config for type tmpfs: invalid
// option: nosuid", awolf 0.6.21; the fake daemon in the unit tests never
// checked). A tmpfs_mb entry used to be a mount.TypeTmpfs. A max_mb entry is a per-workload named volume of the
// local driver backed by a tmpfs of that size: Docker's local driver cannot
// cap a volume otherwise (the size option needs an xfs project quota the
// agent cannot assume), so the cap is real but the space is memory, charged
// to the worker's own cgroup and so bounded by limits.ram_mb as well. Both
// are nosuid, nodev and noexec, except the one entry that declares exec
// (A12), which drops noexec only.
func scratchMounts(e nodewl.Entry, uid int64) ([]mount.Mount, map[string]string) {
	var out []mount.Mount
	var tmpfs map[string]string
	for i, s := range e.Decl.Scratch {
		switch {
		case s.Exec:
			// The exec scratch (i300 A12): the one mount without noexec, so the
			// worker can dlopen what it compiled here. Docker's tmpfs mount type
			// takes a mode but no uid/gid (mount.TmpfsOptions has only SizeBytes,
			// Mode and Options), and a root-owned 1777 tmpfs is not "owned by the
			// worker, 0700"; so BOTH declared kinds take the local-driver tmpfs
			// volume form, sized from whichever of max_mb/tmpfs_mb is set. Still
			// tmpfs-backed (empty at every start, charged to the worker's memory).
			mb := int64(0)
			if s.MaxMB != nil {
				mb = *s.MaxMB
			} else if s.TmpfsMB != nil {
				mb = *s.TmpfsMB
			}
			out = append(out, mount.Mount{
				Type: mount.TypeVolume, Source: workloadVolumeName(e.Addon, e.Name, i), Target: s.Target,
				VolumeOptions: &mount.VolumeOptions{
					NoCopy: true,
					Labels: baseLabels(e, RoleWorker),
					DriverConfig: &mount.Driver{Name: "local", Options: map[string]string{
						"type": "tmpfs", "device": "tmpfs",
						"o": fmt.Sprintf("size=%dm,uid=%d,gid=%d,mode=0700,nosuid,nodev", mb, uid, uid),
					}},
				},
			})
		case s.TmpfsMB != nil:
			if tmpfs == nil {
				tmpfs = map[string]string{}
			}
			tmpfs[s.Target] = fmt.Sprintf("rw,nosuid,nodev,size=%dm,mode=1777", *s.TmpfsMB)
		case s.MaxMB != nil:
			out = append(out, mount.Mount{
				Type: mount.TypeVolume, Source: workloadVolumeName(e.Addon, e.Name, i), Target: s.Target,
				VolumeOptions: &mount.VolumeOptions{
					NoCopy: true,
					Labels: baseLabels(e, RoleWorker),
					DriverConfig: &mount.Driver{Name: "local", Options: map[string]string{
						"type": "tmpfs", "device": "tmpfs",
						"o": fmt.Sprintf("size=%dm,uid=%d,gid=%d,mode=0700,nosuid,nodev,noexec", *s.MaxMB, uid, uid),
					}},
				},
			})
		}
	}
	return out, tmpfs
}

func buildWorker(in specInput) (createSpec, error) {
	e := in.Entry
	d := e.Decl
	env, err := workerEnv(in)
	if err != nil {
		return createSpec{}, err
	}
	var mounts []mount.Mount
	for _, s := range in.Sets {
		mounts = append(mounts, mount.Mount{
			Type: mount.TypeBind, Source: s.Source, Target: s.Target, ReadOnly: true,
			BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate},
		})
	}
	scratch, tmpfs := scratchMounts(e, d.UID)
	mounts = append(mounts, scratch...)

	pids := d.Limits.PIDs
	mem := d.Limits.RAMMB << 20
	host := &container.HostConfig{
		Mounts: mounts,
		Tmpfs:  tmpfs,
		// The worker is in the door's namespace and has no network of its own:
		// it listens on 127.0.0.1 and nothing else can reach it.
		NetworkMode:    container.NetworkMode("container:" + WorkloadDoorName(e.Addon, e.Name)),
		ReadonlyRootfs: true,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		IpcMode:        "private",
		RestartPolicy:  container.RestartPolicy{Name: container.RestartPolicyDisabled},
		Resources: container.Resources{
			Memory:     mem,
			MemorySwap: mem, // equal to Memory: no swap
			NanoCPUs:   int64(d.Limits.CPUs * 1e9),
			PidsLimit:  &pids,
		},
	}
	if d.Accel.GPU > 0 {
		req := container.DeviceRequest{Driver: "nvidia", Capabilities: [][]string{{"gpu"}}}
		if in.GPULeased {
			req.DeviceIDs = in.GPUDevices
		} else {
			req.Count = int(d.Accel.GPU)
		}
		host.Resources.DeviceRequests = []container.DeviceRequest{req}
	}
	cfg := &container.Config{
		Image:  in.WorkerImage,
		User:   strconv.FormatInt(d.UID, 10),
		Env:    env,
		Cmd:    d.Command,
		Labels: workerLabels(e),
	}
	return createSpec{Name: WorkloadContainerName(e.Addon, e.Name), Config: cfg, Host: host}, nil
}

// workloadStunnelConf is the workload door's stunnel.conf: the shape of a
// backend door's (stunnelConf) with one difference that matters. The door
// requires a client certificate from the cluster CA (`verify = 2`) and
// admits ONE name, admitCN (the entry's door.admit[0], this node's agent): a
// `checkHost` line is a DNS-SAN match on the peer's certificate, and with
// verify = 2 a peer that matches none is refused at the handshake. A backend
// door also admits the controller's services; a workload door never does.
// It accepts on acceptHost (the sidecar's own hostname, i.e. its address on
// the workload's network) and connects to the worker on loopback.
func workloadStunnelConf(service, acceptHost string, acceptPort, connectPort int, admitCN string) string {
	return fmt.Sprintf(`; generated by noo-node-agent — the client-certificate door for the node workload %s
foreground = yes
pid =

[%s]
accept = %s:%d
connect = %s:%d
cert = %s/service.crt
key = %s/service.key
CAfile = %s
verify = 2
checkHost = %s
`, service, service, acceptHost, acceptPort, doorLoopback, connectPort, doorLeafDir, doorLeafDir, doorCAPath, admitCN)
}

func buildDoor(in specInput) createSpec {
	e := in.Entry
	name := WorkloadDoorName(e.Addon, e.Name)
	netName := WorkloadNetworkName(e.Addon, e.Name)
	// The one place the leaf is mounted. The CA is the only other file.
	mounts := []mount.Mount{
		{Type: mount.TypeBind, Source: in.CAPath, Target: doorCAPath, ReadOnly: true},
		{Type: mount.TypeBind, Source: in.LeafCrt, Target: doorLeafDir + "/service.crt", ReadOnly: true},
		{Type: mount.TypeBind, Source: in.LeafKey, Target: doorLeafDir + "/service.key", ReadOnly: true},
	}
	conf := workloadStunnelConf(name, name, WorkloadDoorPort, int(e.Decl.Port), in.AdmitCN)
	pids := int64(doorPids)
	host := &container.HostConfig{
		Mounts:        mounts,
		NetworkMode:   container.NetworkMode(netName),
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
		SecurityOpt:   []string{"no-new-privileges"},
		CapDrop:       []string{"ALL"},
		// Root reads the 0600 leaf key through DAC_OVERRIDE, as every backend
		// door does (startSidecar). The port is above 1024: no bind capability.
		CapAdd:    []string{"DAC_OVERRIDE"},
		IpcMode:   "private",
		Resources: container.Resources{Memory: doorMemoryBytes, MemorySwap: doorMemoryBytes, PidsLimit: &pids},
	}
	rootFloor(host, true)
	cfg := &container.Config{
		Image:      in.DoorImage,
		User:       sidecarUser,
		Hostname:   name,
		Env:        []string{"STUNNEL_CONF=" + conf},
		Entrypoint: []string{"sh", "-c"},
		Cmd:        []string{stunnelSidecarScript},
		Labels:     baseLabels(e, RoleDoor),
	}
	net := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{netName: {}}}
	return createSpec{Name: name, Config: cfg, Host: host, Net: net}
}

// buildWorkloadSpecs builds both creates and the hash that names them. The
// hash covers everything either container is made from (the image ID, the
// door image, the conf, the leaf's fingerprint, the sets, the env, the
// limits, the labels), so an unchanged hash on an existing pair is the whole
// idempotence test and any change recreates both.
func buildWorkloadSpecs(in specInput) (workloadSpecs, error) {
	w, err := buildWorker(in)
	if err != nil {
		return workloadSpecs{}, err
	}
	d := buildDoor(in)
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, v := range []any{"i300-f5a/1", in.LeafPrint, d.Config, d.Host, d.Net, w.Config, w.Host} {
		if err := enc.Encode(v); err != nil {
			return workloadSpecs{}, fmt.Errorf("hash spec: %w", err)
		}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	d.Config.Labels[SpecHashLabel] = sum
	w.Config.Labels[SpecHashLabel] = sum
	return workloadSpecs{Door: d, Worker: w, Network: WorkloadNetworkName(in.Entry.Addon, in.Entry.Name), Hash: sum}, nil
}
