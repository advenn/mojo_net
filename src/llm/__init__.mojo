"""Clients for model APIs (docs/llm.md): OpenAI's chat completions and
embeddings, as OpenAI and the servers compatible with it speak them
(vLLM, SGLang, Ollama, Modular's `max serve`), and Anthropic's Messages.

- `types`: the provider-neutral chat (`ChatRequest`, `Message`, `Tool`,
  `ToolCall`, `Reply`, `Delta`, `Usage`, `Embeddings`).
- `openai`, `anthropic`: each API's bodies, replies and stream events,
  sans-I/O.
- `retry`: the SDKs' retry policy.
- `client` (`Client`, `Provider`, `ReplyStream`): the calls, over
  `http.client`; not re-exported here, since it does I/O.
"""

from .error import LlmError
from .retry import RetryPolicy
from .types import ChatRequest, Delta, DeltaKind, Embeddings, Message, Reply, Tool, ToolCall, Usage
