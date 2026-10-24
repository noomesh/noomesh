// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/backendleaves"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
	"github.com/noomesh/noomesh/node-agent-go/internal/sidecarimage"
	"github.com/noomesh/noomesh/node-agent-go/internal/version"
)

// payloadSection adds one named group of fields to a heartbeat or
// registration payload. A section decides for itself between the three
// shapes the gateway tells apart: omitted (an agent that does not report it),
// present-and-empty (reported: nothing), and present. That decision lives
// beside the field it describes, in one place, instead of in a 300-line
// function.
type payloadSection struct {
	name string
	// stage, when set, closes that stage on the heartbeat's stageClock after
	// the section runs, so a slow beat can name the probe that was slow.
	// Registration ignores it.
	stage string
	add   func(r *Reporter, p map[string]any)
}

// The sections both a registration and a heartbeat carry. Each field is
// assembled here and nowhere else.
var (
	secAppVersion = payloadSection{name: "appVersion", add: func(r *Reporter, p map[string]any) {
		// Which node-agent binary this node is running, so the controller can
		// tell rebuilt nodes from stale ones ("dev" = un-stamped build).
		// Refreshed every beat so a mid-session redeploy shows without
		// waiting for re-registration.
		p["app_version"] = version.String()
	}}

	secCapabilities = payloadSection{name: "capabilities", add: func(r *Reporter, p map[string]any) {
		// Static per boot (remembered by Register), so re-sending it every
		// beat is a cheap copy, not a re-probe; it lets the controller heal a
		// KV/DB record that lost them.
		p["capabilities"] = r.caps
	}}

	secPosture = payloadSection{name: "posture", add: func(r *Reporter, p map[string]any) {
		// Posture, on every beat and at registration: a running agent
		// requires a client certificate on its control API, and `noo cluster
		// verify` judges the node on this field.
		p["peer_identity_enforced"] = auth.PeerIdentityEnforced(r.cfg)
		// This agent admits the controller's leaf with no bearer
		// (auth.ControllerLeafOrToken), so the gateway drops
		// NOO_NODE_AGENT_TOKEN for this node. An agent that omits it keeps
		// receiving the bearer — both roll orders stay safe.
		p["controller_leaf_only"] = auth.ControllerLeafOnly(r.cfg)
		p["control_transports"] = r.controlTransports()
	}}

	secBackendLeaves = payloadSection{name: "backendLeaves", stage: "backend_leaves", add: func(r *Reporter, p map[string]any) {
		// The door leaves this node HOLDS, with each leaf's DNS SANs and
		// NotAfter. ALWAYS sent, including empty — `{}` is "holds none", and
		// absence is what an agent too old to report looks like, which
		// `noo cluster verify` reads as WARN, not as proof. The key beside
		// each leaf is never opened.
		p["backend_leaves"] = backendleaves.Report()
	}}

	secDataRoots = payloadSection{name: "dataRoots", stage: "data_roots", add: func(r *Reporter, p map[string]any) {
		// The data roots this node resolves and the host paths its managed
		// backend containers mount, so a provision bundle can refuse to
		// relocate a node off the root it runs on. Always sent.
		p["data_roots"] = r.dataRoots()
	}}

	secLegacyLanes = payloadSection{name: "legacyLanes", add: func(r *Reporter, p map[string]any) {
		// Legacy credential lanes admitted since start: {since_unix,
		// static_token, whois_non_controller}. Every lane is always present,
		// zeros included — absence reads as an agent too old to report, not
		// as "0 uses".
		p["legacy_lanes"] = auth.LegacyLaneSnapshot()
	}}

	secImageProvenance = payloadSection{name: "imageProvenance", add: func(r *Reporter, p map[string]any) {
		// "published" or "fallback-alpine" for the stunnel sidecar image.
		// Omitted until a sidecar has been started.
		if si := sidecarimage.Report(); si != "" {
			p["stunnel_image"] = si
		}
		// Where each image this process started a container from came from:
		// "rail" | "local" | "registry". Omitted until a start.
		if is := imagesource.Report(); is != nil {
			p["image_sources"] = is
		}
		// rail | legacy — NOO_IMAGE_SOURCE, the rollout switch.
		p["image_source_mode"] = imagesource.Mode()
	}}

	secBackendContainers = payloadSection{name: "backendContainers", stage: "backend_containers", add: func(r *Reporter, p map[string]any) {
		// Per running backend container: start time and health. `{}` is sent
		// (nothing running); omitted only when docker could not be listed or
		// the provider is not installed, which the CLI reads as "not
		// reported".
		if bc := r.backendContainersReport(); bc != nil {
			p["backend_containers"] = bc
		}
	}}

	secModelPresence = payloadSection{name: "modelPresence", add: func(r *Reporter, p map[string]any) {
		// Per placed backend: does its model server HOLD the placement's
		// model. ALWAYS sent, `{}` included: absence of the key is what an
		// older agent looks like, and the gateway reads that as unknown.
		p["model_presence"] = modelpresence.Report()
		if ms := r.modelStats(); len(ms) > 0 {
			p["model_stats"] = ms
		}
	}}

	secGPUContention = payloadSection{name: "gpuContention", add: func(r *Reporter, p map[string]any) {
		// Shared-GPU contention (internal/gpuyield): is something outside
		// noomesh using the GPU, and are our GPU backends paused for it.
		// Omitted only when the yield is not wired.
		if gc := r.gpuContentionReport(); gc != nil {
			p["gpu_contention"] = gc
		}
	}}
)

// registerSections is what a registration carries beyond its identity keys
// (node_id, hostname, ip_address, dialable address). All shared with the beat.
var registerSections = []payloadSection{
	secAppVersion, secCapabilities, secPosture, secBackendLeaves, secDataRoots,
	secLegacyLanes, secImageProvenance, secBackendContainers, secModelPresence,
	secGPUContention,
}

// heartbeatSections is everything a beat adds after its base (metrics, GPU
// identity, address, sensors, companion telemetry). Order matters only for
// the stage clock: a stage is closed after the section that carries its name.
var heartbeatSections = []payloadSection{
	secAppVersion,
	secCapabilities,
	secBusStatus,
	secPullEmbed,
	secBackendRuntimes,
	secLoadedModels,
	secCertExpiry,
	secRefusals,
	secHostServices,
	secModelBench,
	secHostd,
	secLogShip,
	secPosture,
	secBackendLeaves,
	secDataRoots,
	secLegacyLanes,
	secImageProvenance,
	secBackendContainers,
	secModelPresence,
	secGPUContention,
}

// Heartbeat-only sections.
var (
	secBusStatus = payloadSection{name: "busStatus", stage: "bus", add: func(r *Reporter, p map[string]any) {
		// This node's own view of its NATS bus. OMITTED, not nulled, when
		// this agent has no messaging subsystem — so the gateway can tell
		// "this build does not report it" from "reported as down".
		if bus := r.natsStatus(); bus != nil {
			p["nats_status"] = bus
		}
	}}

	secPullEmbed = payloadSection{name: "pullEmbed", add: func(r *Reporter, p map[string]any) {
		if r.pullEmbed != nil {
			if pe := r.pullEmbed(); pe != nil {
				p["pull_embed"] = pe
			}
		}
	}}

	secBackendRuntimes = payloadSection{name: "backendRuntimes", add: func(r *Reporter, p map[string]any) {
		// Omitted, never empty: an older agent reports nothing here, and the
		// controller must not read that as "every backend is
		// container-managed".
		if r.getRuntimes != nil {
			if rt := r.getRuntimes(); len(rt) > 0 {
				p["backend_runtimes"] = rt
			}
		}
	}}

	secLoadedModels = payloadSection{name: "loadedModels", stage: "runtimes", add: func(r *Reporter, p map[string]any) {
		// What an adopted server has loaded, beside — never instead of — what
		// it is placed to serve. Omitted when nothing is loaded or the agent
		// has no adopted lane.
		if r.getLoaded != nil {
			if lm := r.getLoaded(); len(lm) > 0 {
				p["loaded_models"] = lm
			}
		}
	}}

	secCertExpiry = payloadSection{name: "certExpiry", add: func(r *Reporter, p map[string]any) {
		// NotAfter of the cert this agent is PRESENTING: positive proof a
		// rotated cert is live, which "the node came back online" is not.
		// Omitted (not nulled) when unreadable — an older agent or a TLS-less
		// config, both honest answers.
		if na := servedCertNotAfter(r.cfg.TLSCert); na > 0 {
			p["cert_not_after"] = na
		}
	}}

	secRefusals = payloadSection{name: "refusalsAlwaysSent", add: func(r *Reporter, p map[string]any) {
		// Desired-state instructions this node DECLINED (internal/refusals).
		//
		// ALWAYS sent, INCLUDING empty — and that is the fix, not an oversight
		// reversed. The gateway documents the three-way reading ("ABSENT is
		// not EMPTY ... an agent that sends an empty list IS saying 'nothing
		// refused', and that does clear it", routes/cluster.rs); omitting the
		// empty case made the clearing branch unreachable and a refusal that
		// RESOLVED stayed on the node record forever (found 2026-09-19: host3's
		// harness refusal would have outlived its own fix). Absence still
		// means "an agent too old to have this code", which the gateway must
		// not clear on.
		p["reconcile_refusals"] = refusals.List()
	}}

	secHostServices = payloadSection{name: "hostServices", stage: "host_services", add: func(r *Reporter, p map[string]any) {
		// Host services this node runs beside its containers (the harness).
		// Omitted when unreported, never faked as stopped.
		if r.hostState != nil {
			if hs := r.hostState(); len(hs) > 0 {
				p["host_services"] = hs
			}
		}
	}}

	secModelBench = payloadSection{name: "modelBench", add: func(r *Reporter, p map[string]any) {
		// The last measured model speed (POST /bench); the controller
		// resolves a measured first_byte_secs from it. Omitted until a bench
		// has run on this agent (kept in memory only).
		if r.modelBench != nil {
			if mb := r.modelBench(); mb != nil {
				p["model_bench"] = mb
			}
		}
	}}

	secHostd = payloadSection{name: "hostd", stage: "hostd", add: func(r *Reporter, p map[string]any) {
		// The confined-root daemon that performs privileged ops for this
		// unprivileged agent. Omitted when unreported.
		if r.hostdState != nil {
			if hd := r.hostdState(); len(hd) > 0 {
				p["hostd"] = hd
			}
		}
	}}

	secLogShip = payloadSection{name: "logShip", stage: "log_ship", add: func(r *Reporter, p map[string]any) {
		// The log shipper's own account (queued / shipped / last accepted /
		// last error). Omitted only by an agent build without one.
		if r.logShipState != nil {
			if ls := r.logShipState(); len(ls) > 0 {
				p["log_ship"] = ls
			}
		}
	}}
)

// companionTelemetry adds the battery/thermal/network fields. The gateway
// persists them (routes/cluster.rs) and CompanionPolicy gates on them;
// reporting them every beat makes the sensor list self-maintaining (plug in
// a webcam and the next beat advertises it). Sent by every tier.
func (r *Reporter) companionTelemetry(p map[string]any, power hardware.PowerStatus) {
	p["battery_pct"] = power.BatteryPct // null on mains-powered hosts
	p["is_charging"] = power.IsCharging
	p["power_source"] = power.PowerSource
	p["network_type"] = power.NetworkType
	p["thermal_state"] = power.ThermalState
}
