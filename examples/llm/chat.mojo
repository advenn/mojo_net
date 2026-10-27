"""Stream a model's answer over an OpenAI-compatible API (a local
`max serve`, vLLM, Ollama, OpenAI itself) or Anthropic's.

    pixi run mojo run -I src examples/llm/chat.mojo http://localhost:8000/v1 MODEL "Why is the sky blue?"
    OPENAI_API_KEY=... pixi run mojo run -I src examples/llm/chat.mojo https://api.openai.com/v1 gpt-4o-mini "Hi"
    ANTHROPIC_API_KEY=... pixi run mojo run -I src examples/llm/chat.mojo https://api.anthropic.com/v1 claude-sonnet-4-5 "Hi"

The provider is Anthropic's when the URL's host is api.anthropic.com. A
key is sent only to the host given; use https:// for any remote API.
"""

from std.os import getenv
from std.sys import argv

from http.client import Url
from llm import ChatRequest, Delta, DeltaKind, Message
from llm.client import Client, Provider


def main() raises:
    var args = argv()
    if len(args) != 4:
        print("usage: chat.mojo BASE_URL MODEL PROMPT")
        return
    var base = String(args[1])
    var anthropic = Url.parse(base).host == "api.anthropic.com"  # (the host itself, not a substring)
    var key = getenv("ANTHROPIC_API_KEY") if anthropic else getenv("OPENAI_API_KEY")
    var client = Client(Provider.ANTHROPIC if anthropic else Provider.OPENAI, base, key)
    var req = ChatRequest(String(args[2]), [Message.system("Answer briefly."), Message.user(String(args[3]))])
    req.max_tokens = 512
    var stream = client.stream(req)
    var d = Delta()
    while stream.next(d):
        if d.kind == DeltaKind.TEXT:
            print(d.text, end="")
        elif d.kind == DeltaKind.DONE:
            print("\n[", d.text, "; ", d.usage, "]", sep="")
