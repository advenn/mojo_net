"""JSON (RFC 8259) in pure Mojo (docs/json.md).

- `document`: `parse` (strict) into a `Document`, a flat tree with typed
  accessors; `Limits`, `Kind`; `Dialect` for what Python's json reads
  besides; `Visitor` for walking a document in order (`Document.visit`).
- `writer`: `Writer`, JSON text built call by call, its structure checked.
- `ryu`: `write_float` and `format_float`, the shortest text that reads
  back as the same Float64 (Ryū), laid out as JSON.stringify does.
- `number`: `read_float`, a number's text read as the nearest Float64
  (Clinger's fast path, then Eisel-Lemire).
"""

from .document import DEFAULT_MAX_DEPTH, DEFAULT_MAX_SIZE, MAX_SIZE, SPAN_SLACK, Dialect, Document, Kind, Limits, Visitor, parse
from .error import JsonError
from .number import read_float
from .ryu import format_float, write_float
from .writer import Writer
