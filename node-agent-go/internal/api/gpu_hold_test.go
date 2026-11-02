// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/gpuyield"
)

// The hold/release routes carry the lease fields to gpuyield and map its
// refusals to 409s with a machine-readable code (noomesh-internal i163 C/D).
func TestGPUHoldAndReleaseCarryTheLeaseAndMapRefusals(t *testing.T) {
	var gotHold gpuyield.HoldRequest
	var gotRel gpuyield.ReleaseRequest
	var holdErr, relErr error
	s := &Server{}
	s.SetGPUHold(
		func(_ context.Context, req gpuyield.HoldRequest) (gpuyield.Contention, error) {
			gotHold = req
			return gpuyield.Contention{State: "held", Lease: &gpuyield.Lease{OperationID: req.OperationID, Generation: 7}}, holdErr
		},
		func(_ context.Context, req gpuyield.ReleaseRequest) (gpuyield.Contention, error) {
			gotRel = req
			return gpuyield.Contention{State: "free"}, relErr
		},
	)
	do := func(h http.HandlerFunc, body string) (int, map[string]any) {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, "/gpu/x", strings.NewReader(body)))
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	code, out := do(s.handleGPUHold, `{"reason":"voice","owner":"rbwolf","operation_id":"op-1","workload":"pai-voice/voice-worker","mode":"drain","timeout_secs":30}`)
	if code != 200 || out["status"] != "held" {
		t.Fatalf("%d %v", code, out)
	}
	if gotHold.OperationID != "op-1" || gotHold.Owner != "rbwolf" || gotHold.Mode != "drain" || gotHold.Workload != "pai-voice/voice-worker" || gotHold.Timeout != 30*time.Second || gotHold.Force {
		t.Fatalf("hold request: %+v", gotHold)
	}
	if lease := out["gpu_contention"].(map[string]any)["lease"].(map[string]any); lease["generation"] != float64(7) {
		t.Fatalf("the lease rides the answer: %v", out)
	}
	// i344b: the operator's own use is carried as `purpose`.
	if code, out = do(s.handleGPUHold, `{"operation_id":"op-u","purpose":"user"}`); code != 200 || gotHold.Purpose != "user" {
		t.Fatalf("purpose: %d %v %+v", code, out, gotHold)
	}

	// Refusals.
	holdErr = &gpuyield.ErrHeld{Current: gpuyield.Lease{Owner: "a", OperationID: "op-0", Generation: 6}}
	code, out = do(s.handleGPUHold, `{"operation_id":"op-2"}`)
	if code != 409 || out["error"] != "held_by_other" || out["current"].(map[string]any)["operation_id"] != "op-0" {
		t.Fatalf("held by other: %d %v", code, out)
	}
	holdErr = &gpuyield.ErrDrainTimeout{Timeout: 2 * time.Minute, Remaining: map[string]int{"vllm": 1}}
	code, out = do(s.handleGPUHold, `{"operation_id":"op-2"}`)
	if code != 409 || out["error"] != "drain_timeout" || out["status"] != "needs_attention" || out["in_flight"].(map[string]any)["vllm"] != float64(1) {
		t.Fatalf("drain timeout: %d %v", code, out)
	}
	holdErr = gpuyield.ErrTransition
	if code, out = do(s.handleGPUHold, `{"operation_id":"op-2"}`); code != 409 || out["error"] != "transition_in_progress" {
		t.Fatalf("transition: %d %v", code, out)
	}
	holdErr = nil

	// Release: ids, force, resume now; no ids = legacy force.
	code, out = do(s.handleGPURelease, `{"operation_id":"op-1","generation":7,"resume":"now"}`)
	if code != 200 || out["status"] != "released" || gotRel.OperationID != "op-1" || gotRel.Generation != 7 || !gotRel.ResumeNow || gotRel.Force {
		t.Fatalf("release: %d %v %+v", code, out, gotRel)
	}
	do(s.handleGPURelease, `{}`)
	if !gotRel.Force || gotRel.ResumeNow {
		t.Fatalf("a bare release is a force: %+v", gotRel)
	}
	relErr = gpuyield.ErrNotHeld
	if code, out = do(s.handleGPURelease, `{"operation_id":"op-9","generation":1}`); code != 409 || out["error"] != "not_held" {
		t.Fatalf("not held: %d %v", code, out)
	}
}
