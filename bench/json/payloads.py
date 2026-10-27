"""The JSON documents bench/json measures, shaped as AI APIs send them
(OpenAI-style chat completions, a streamed chunk, embeddings, a request
with tool schemas), and the same work done by Python's json module (its C
accelerator) as the baseline.

    python3 bench/json/payloads.py write <dir>   write the payloads
    python3 bench/json/payloads.py python <dir>  time Python's json on them
"""

import json
import os
import random
import sys
import time


def chat_completion():
    return {
        "id": "chatcmpl-9x3AbCdEfGhIjKlMnOpQrStUv",
        "object": "chat.completion",
        "created": 1730000000,
        "model": "gpt-4o-mini-2024-07-18",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Mojo is a programming language that combines Python's syntax with systems "
                    "programming features. It compiles through MLIR, so the same code can target CPUs "
                    "and GPUs. Été: \"quoted\" and a newline\nhere.",
                    "refusal": None,
                },
                "logprobs": None,
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 42, "completion_tokens": 64, "total_tokens": 106},
        "system_fingerprint": "fp_0123456789",
    }


def chunk():
    return {
        "id": "chatcmpl-9x3AbCdEfGhIjKlMnOpQrStUv",
        "object": "chat.completion.chunk",
        "created": 1730000000,
        "model": "gpt-4o-mini-2024-07-18",
        "choices": [{"index": 0, "delta": {"content": " world"}, "logprobs": None, "finish_reason": None}],
    }


def embeddings(rng):
    return {
        "object": "list",
        "data": [
            {"object": "embedding", "index": i, "embedding": [rng.uniform(-0.1, 0.1) for _ in range(1536)]}
            for i in range(16)
        ],
        "model": "text-embedding-3-small",
        "usage": {"prompt_tokens": 512, "total_tokens": 512},
    }


def tools_request():
    params = {
        "type": "object",
        "properties": {
            "location": {"type": "string", "description": "City and country, e.g. Tashkent, Uzbekistan"},
            "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
            "days": {"type": "integer", "minimum": 1, "maximum": 14},
        },
        "required": ["location"],
        "additionalProperties": False,
    }
    return {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What's the weather in Tashkent this week?"},
        ],
        "tools": [
            {"type": "function", "function": {"name": "get_weather_%d" % i, "description": "Get the weather forecast", "parameters": params}}
            for i in range(8)
        ],
        "temperature": 0.2,
        "stream": True,
    }


def payloads():
    rng = random.Random(1)
    return {
        "chat_completion": chat_completion(),
        "chunk": chunk(),
        "embeddings": embeddings(rng),
        "tools_request": tools_request(),
    }


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("write", "python"):
        sys.exit(__doc__)
    out = sys.argv[2]
    if sys.argv[1] == "write":
        os.makedirs(out, exist_ok=True)
        for name, v in payloads().items():
            with open(os.path.join(out, name + ".json"), "w") as f:
                f.write(json.dumps(v, ensure_ascii=False, separators=(",", ":")))
        return
    for name in ("chunk", "chat_completion", "tools_request", "embeddings"):
        with open(os.path.join(out, name + ".json"), "rb") as f:
            data = f.read()
        text = data.decode("utf-8")
        n = max(1, 20_000_000 // len(data))
        best_load = best_dump = float("inf")
        v = json.loads(text)
        for _ in range(5):
            t = time.perf_counter()
            for _ in range(n):
                json.loads(text)
            best_load = min(best_load, (time.perf_counter() - t) / n)
            t = time.perf_counter()
            for _ in range(n):
                json.dumps(v, ensure_ascii=False, separators=(",", ":"))
            best_dump = min(best_dump, (time.perf_counter() - t) / n)
        print(
            "python %-16s %8d bytes  loads %9.2f us (%6.0f MB/s)  dumps %9.2f us"
            % (name, len(data), best_load * 1e6, len(data) / best_load / 1e6, best_dump * 1e6)
        )


if __name__ == "__main__":
    main()
