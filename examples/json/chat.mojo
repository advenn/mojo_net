"""An OpenAI-style chat request written with `json.Writer`, and a response
read with `json.parse` (no network: the response is a literal).

    pixi run mojo run -I src examples/json/chat.mojo
"""

from json import Writer, parse


def request(model: String, prompt: String, temperature: Float64) raises -> List[UInt8]:
    var w = Writer()
    w.begin_object()
    w.key("model")
    w.string(model)
    w.key("messages")
    w.begin_array()
    w.begin_object()
    w.key("role")
    w.string("user")
    w.key("content")
    w.string(prompt)
    w.end_object()
    w.end_array()
    w.key("temperature")
    w.float(temperature)
    w.key("stream")
    w.bool(False)
    w.end_object()
    return w.take()


def main() raises:
    var body = request("gpt-4o-mini", 'Say "hi"\nin one word.', 0.2)
    print("request: ", String(unsafe_from_utf8=Span(body)))

    var doc = parse(
        """{"id": "chatcmpl-1", "object": "chat.completion", "created": 1730000000,
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "Hi!"}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 2, "total_tokens": 14}}"""
    )
    var choice = doc.child(doc.member(0, "choices"), 0)
    var message = doc.member(choice, "message")
    print("content: ", doc.text(doc.member(message, "content")))
    print("finish:  ", doc.text(doc.member(choice, "finish_reason")))
    var usage = doc.member(0, "usage")
    print("tokens:  ", doc.int(doc.member(usage, "total_tokens")))
    # A field that may be absent: get() returns None instead of raising.
    if not doc.get(message, "tool_calls"):
        print("no tool calls")
