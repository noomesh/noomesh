// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

// The agent's fixed reason vocabulary: the `reason` of a node_workloads or
// model_sets heartbeat row. docs/reference/node-workloads.md ("Reasons")
// lists each with its remedy, and tests/test_i300_fixture_parity.py holds
// the two lists equal. A reason is a code, never free text.
const (
	ReasonDeclInvalid          = "decl_invalid"
	ReasonDesiredInvalid       = "desired_invalid"
	ReasonDoorLeafMissing      = "door_leaf_missing"
	ReasonImageMissing         = "image_missing"
	ReasonImageDigestMismatch  = "image_digest_mismatch"
	ReasonSetMissing           = "set_missing"
	ReasonSetSlotInvalid       = "set_slot_invalid"
	ReasonSetUnverified        = "set_unverified"
	ReasonProfileInvalid       = "profile_invalid"
	ReasonDisk                 = "disk"
	ReasonConsentNone          = "consent_none"
	ReasonConsentUnapproved    = "consent_unapproved"
	ReasonNvidiaRuntimeMissing = "nvidia_runtime_missing"
	ReasonDriverCapsMissing    = "driver_caps_missing"
	ReasonComputeCapLow        = "compute_cap_low"
	ReasonArchMismatch         = "arch_mismatch"
	ReasonControllerHost       = "controller_host"
	ReasonAdmitInvalid         = "admit_invalid"
	ReasonEnvOutOfBounds       = "env_out_of_bounds"
	ReasonContainerConflict    = "container_conflict"
	ReasonStartTimeout         = "start_timeout"
	ReasonCrashed              = "crashed"
	ReasonDrainTimeout         = "drain_timeout" // reported as needs_attention
	ReasonDoorUnreachable      = "door_unreachable"
)

// Reasons is every reason, in the order the contract document lists them.
var Reasons = []string{
	ReasonDeclInvalid, ReasonDesiredInvalid, ReasonDoorLeafMissing, ReasonImageMissing,
	ReasonImageDigestMismatch, ReasonSetMissing, ReasonSetSlotInvalid, ReasonSetUnverified,
	ReasonProfileInvalid, ReasonDisk, ReasonConsentNone, ReasonConsentUnapproved, ReasonNvidiaRuntimeMissing,
	ReasonDriverCapsMissing, ReasonComputeCapLow, ReasonArchMismatch, ReasonControllerHost,
	ReasonAdmitInvalid, ReasonEnvOutOfBounds, ReasonContainerConflict, ReasonStartTimeout,
	ReasonCrashed, ReasonDrainTimeout, ReasonDoorUnreachable,
}
