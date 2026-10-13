// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

// Executable is the set of job types this node-agent can run — one entry
// per case in the `switch job.Type` of Executor.runJob.
//
// It exists so a dispatch of an unrunnable type can be rejected *before*
// the job is accepted and a goroutine is spawned, and so the set is stated
// once rather than being implied by the switch alone. The authoritative
// cross-executor table (which types exist, and whether a node or the
// gateway runs each) lives in gateway-rust/src/job_types.rs;
// tests/test_job_type_declarations.py asserts this map still agrees with
// it.
//
// "background_embed" was retired (see RETIRED_JOB_TYPES in job_types.rs):
// it only POSTed back to the controller's /api/memory/embed/start, which
// the gateway now drives itself.
//
// Note: "warm_embeddings"/"warm_entities" are *actions* inside a
// background_cache payload, not job types.
var Executable = map[string]bool{
	"inference":        true,
	"tool_exec":        true,
	"model_download":   true,
	"background_graph": true,
	"background_cache": true,
	"fetch_bundle":     true,
	"model_file":       true,
}

// CanExecute reports whether this node-agent has an executor for jobType.
func CanExecute(jobType string) bool {
	return Executable[jobType]
}
