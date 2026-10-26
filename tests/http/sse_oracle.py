"""A reference parser for text/event-stream, written from the WHATWG HTML
standard's text ("9.2.6 Interpreting an event stream"), for differential
tests of src/http/sse.mojo (test-only Python; not a test file itself).

    parse(data: bytes) -> (events, last_event_id, retry_ms, discarded)

Each event is (type, data, last_event_id). It works on the whole stream at
once, unlike the parser under test, which sees it in pieces.
"""


def _lines(text):
    """Split into lines at CRLF, LF or CR; the last element is what follows
    the last line end (an unfinished line)."""
    out, cur, i = [], [], 0
    while i < len(text):
        c = text[i]
        if c == "\r":
            out.append("".join(cur))
            cur = []
            if i + 1 < len(text) and text[i + 1] == "\n":
                i += 1
        elif c == "\n":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    return out, "".join(cur)


def parse(data):
    # "decoded using UTF-8 decode": a leading BOM is stripped, errors replaced.
    text = data.decode("utf-8", errors="replace")
    if text.startswith("﻿"):
        text = text[1:]
    lines, rest = _lines(text)
    events = []
    data_buf, type_buf, id_buf, last_id, retry = "", "", "", "", None
    for line in lines:
        if line == "":
            # Dispatch the event.
            last_id = id_buf
            if data_buf == "":
                type_buf = ""
                continue
            if data_buf.endswith("\n"):
                data_buf = data_buf[:-1]
            events.append((type_buf or "message", data_buf, last_id))
            data_buf, type_buf = "", ""
            continue
        if line.startswith(":"):
            continue
        if ":" in line:
            field, value = line.split(":", 1)
            if value.startswith(" "):
                value = value[1:]
        else:
            field, value = line, ""
        if field == "event":
            type_buf = value
        elif field == "data":
            data_buf += value + "\n"
        elif field == "id":
            if "\0" not in value:
                id_buf = value
        elif field == "retry":
            if value and all(c in "0123456789" for c in value):
                retry = int(value)
    # "Once the end of the file is reached, any pending data must be
    # discarded." (an unfinished line, or an event with no empty line yet)
    discarded = rest != "" or data_buf != "" or type_buf != ""
    return events, last_id, retry, discarded
