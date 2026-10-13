// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"strings"
	"testing"
)

// tool_exec used to return {"status":"executed"} without executing
// anything: the scheduler marked the job complete, the dashboard showed a
// green run, and no tool had been called. A verdict assembled from your own
// echo is worse than an error, because nothing downstream can tell it from
// work.
func TestToolExecRefusesInsteadOfFakingSuccess(t *testing.T) {
	e := &Executor{}
	res, err := e.executeTool(map[string]any{"tool": "shell", "args": map[string]any{"cmd": "id"}})
	if err == nil {
		t.Fatal("tool_exec must return an error, not a fabricated success")
	}
	if res != nil {
		t.Errorf("a refusal must carry no result, got %v", res)
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("the error must say the node does not run tools, got %q", err)
	}
	if strings.Contains(err.Error(), "executed") && !strings.Contains(err.Error(), "previously") {
		t.Errorf("the error must not read as a success, got %q", err)
	}
}
