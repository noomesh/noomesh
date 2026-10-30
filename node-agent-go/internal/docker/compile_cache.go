// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

// vLLM's compile caches, kept across container recreates (followup i305).
//
// vLLM compiles on its first requests after every start: torch.compile
// (Inductor) for the model graph and Triton for its attention kernels
// (`jit_monitor.py`: "Triton kernel JIT compilation during inference:
// kernel_unified_attention"). Each cache lived in the container layer
// (`/root/.triton`, `/root/.cache/vllm`; `docker diff` on awolf), so a roll or
// a restart paid the whole compile again on the first chat (~25 s).
//
// Where each one goes, read from the pinned versions (vLLM v0.25.0):
//   - VLLM_CACHE_ROOT (vllm/envs.py, default $XDG_CACHE_HOME/vllm, i.e.
//     ~/.cache/vllm): vLLM's torch.compile cache is
//     VLLM_CACHE_ROOT/torch_compile_cache/<hash> (compilation/backends.py),
//     and its Inductor adaptor points TORCHINDUCTOR_CACHE_DIR and
//     TRITON_CACHE_DIR at <that dir>/inductor_cache and /triton_cache
//     in-process (compilation/compiler_interface.py, initialize_cache).
//   - TRITON_CACHE_DIR (triton knobs.py, default $TRITON_HOME/.triton/cache):
//     a plain @triton.jit kernel compiled before or outside that adaptor.
//   - TORCHINDUCTOR_CACHE_DIR: Inductor outside vLLM's own compile.
//   - FLASHINFER_WORKSPACE_BASE (flashinfer/jit/env.py, default $HOME):
//     FlashInfer's runtime JIT workspace, <base>/.cache/flashinfer. The image
//     ships flashinfer-jit-cache, so this only holds what that lacks.
//
// One named Docker volume, not a bind under the data root: it holds no model
// and no secret, only compiled kernels the engine can rebuild, so it is not a
// host root the data-root policy has to judge, needs no directory the agent
// must create first (requireMountSources refuses a missing bind source and
// would have refused every vLLM start on a node that lacked it), and leaves
// no root-owned files in the agent's data root. Docker creates it on the
// first start. The default vllm-openai image keeps `USER root` (its
// Dockerfile, "vllm-base" stage), and the agent runs it without a user or a
// read-only root, so the engine writes the volume as it wrote the layer.
// The cache keys are hashes of model, config and code, so one volume serves
// every model a node runs; a different image recompiles into a new key.
const (
	// VLLMCompileCacheVolume is the agent's named volume. The compose vllm
	// services use their own (project-scoped) volume: the two never run at
	// once under one name, and a shared one would make compose warn about a
	// volume it did not create.
	VLLMCompileCacheVolume = "noo-vllm-compile-cache"
	// VLLMCompileCacheTarget is vLLM's own default cache root for a root
	// user, so the mount still catches the torch.compile cache if the env
	// below were ever dropped.
	VLLMCompileCacheTarget = "/root/.cache/vllm"
)
