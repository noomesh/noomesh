// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// vllmArgsFor runs the REAL vllmEntrypointScript under sh with a stub
// python3 that records its argv, and returns the engine argument line and the
// script's own output. Nothing is mocked in the script: the flag logic under
// test is the shell the container runs (followup i344a).
func vllmArgsFor(t *testing.T, batched *string) (args, out string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	bin := t.TempDir()
	stub := "#!/bin/sh\n" +
		"case \"$1\" in -c) exit 1 ;; esac\n" +
		"echo \"ENGINE_ARGS: $*\"\n"
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", vllmEntrypointScript)
	env := []string{
		"PATH=" + bin + ":/usr/bin:/bin",
		"VLLM_MODEL=test/model-AWQ",
		"GPU_MEMORY_UTILIZATION=0.9",
		"VLLM_MAX_MODEL_LEN=16384",
		"TENSOR_PARALLEL_SIZE=1",
		"VLLM_TOOL_PARSER=hermes",
		"VLLM_REASONING_PARSER=none-needed",
	}
	if batched != nil {
		env = append(env, "VLLM_MAX_NUM_BATCHED_TOKENS="+*batched)
	}
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, b)
	}
	out = string(b)
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "ENGINE_ARGS: ") {
			args = strings.TrimPrefix(l, "ENGINE_ARGS: ")
		}
	}
	if args == "" {
		t.Fatalf("engine was never launched:\n%s", out)
	}
	return args, out
}

func TestVLLMBatchedTokensUnsetIsByteIdentical(t *testing.T) {
	const want = "-m vllm.entrypoints.openai.api_server --model test/model-AWQ --quantization awq " +
		"--gpu-memory-utilization 0.9 --max-model-len 16384 --tensor-parallel-size 1 " +
		"--enable-auto-tool-choice --tool-call-parser hermes --host 127.0.0.1 --port 8000 " +
		"--reasoning-parser none-needed"
	empty := ""
	for name, v := range map[string]*string{"unset": nil, "empty": &empty} {
		args, _ := vllmArgsFor(t, v)
		if args != want {
			t.Errorf("%s: args changed\n got: %q\nwant: %q", name, args, want)
		}
		if strings.Contains(args, "max-num-batched-tokens") {
			t.Errorf("%s: flag present", name)
		}
	}
}

func TestVLLMBatchedTokensSetAddsTheFlag(t *testing.T) {
	v := "8192"
	args, _ := vllmArgsFor(t, &v)
	if !strings.HasSuffix(args, " --max-num-batched-tokens 8192") {
		t.Errorf("flag missing or misplaced: %q", args)
	}
	if strings.Count(args, "--max-num-batched-tokens") != 1 {
		t.Errorf("flag must appear once: %q", args)
	}
}

func TestVLLMBatchedTokensGarbageIsIgnoredAndSaid(t *testing.T) {
	for _, v := range []string{"abc", "0", "00", "-5", "8k", "1.5", "8192 --foo", " 8192", "$(id)"} {
		v := v
		args, out := vllmArgsFor(t, &v)
		if strings.Contains(args, "max-num-batched-tokens") || strings.Contains(args, "--foo") {
			t.Errorf("%q passed through: %q", v, args)
		}
		if !strings.Contains(out, "Ignoring VLLM_MAX_NUM_BATCHED_TOKENS") {
			t.Errorf("%q ignored silently:\n%s", v, out)
		}
	}
}
