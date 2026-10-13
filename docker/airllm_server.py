# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Simple FastAPI server for AirLLM."""

import os
from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="AirLLM Server")

# Global model instance (lazy loaded)
model = None


def load_model():
    """Load AirLLM model (lazy initialization)."""
    global model
    if model is not None:
        return model

    from airllm import AutoModel

    model_path = os.getenv("MODEL_PATH", "meta-llama/Llama-2-70b-hf")
    max_vram_gb = float(os.getenv("MAX_VRAM_GB", "8.0"))
    compression = os.getenv("COMPRESSION", "4bit")

    print(f"Loading AirLLM model: {model_path}")
    print(f"  Max VRAM: {max_vram_gb}GB")
    print(f"  Compression: {compression}")

    model = AutoModel.from_pretrained(
        model_path,
        compression=compression,
        max_memory={0: f"{max_vram_gb}GB"},
        cache_dir="/cache",
    )

    print("Model loaded successfully!")
    return model


class CompletionRequest(BaseModel):
    prompt: str
    max_tokens: int = 2048
    temperature: float = 0.7
    top_p: float = 0.9
    stream: bool = False


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy", "model_loaded": model is not None}


@app.get("/v1/models")
def list_models():
    """List available models (OpenAI-compatible)."""
    model_path = os.getenv("MODEL_PATH", "meta-llama/Llama-2-70b-hf")
    return {
        "data": [
            {
                "id": model_path.split("/")[-1],
                "object": "model",
                "owned_by": "airllm",
            }
        ]
    }


@app.post("/v1/completions")
def create_completion(request: CompletionRequest):
    """Generate completion (OpenAI-compatible)."""
    llm = load_model()

    output = llm.generate(
        request.prompt,
        max_new_tokens=request.max_tokens,
        temperature=request.temperature,
        top_p=request.top_p,
        do_sample=True,
    )

    generated_text = output[0] if isinstance(output, list) else output

    return {
        "id": "airllm-completion",
        "object": "text_completion",
        "created": 0,
        "model": os.getenv("MODEL_PATH", "airllm"),
        "choices": [
            {
                "text": generated_text,
                "index": 0,
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": len(request.prompt.split()),
            "completion_tokens": len(generated_text.split()),
            "total_tokens": len(request.prompt.split()) + len(generated_text.split()),
        },
    }


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))

    uvicorn.run(app, host=host, port=port)
