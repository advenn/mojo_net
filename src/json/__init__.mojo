"""JSON (RFC 8259) in pure Mojo (docs/json.md).

- `document`: `parse` (strict) into a `Document`, a flat tree with typed
  accessors; `Limits`, `Kind`.
- `writer`: `Writer`, JSON text built call by call, its structure checked.
- `ryu`: `write_float` and `format_float`, the shortest text that reads
  back as the same Float64 (Ryū), laid out as JSON.stringify does.
"""

from .document import DEFAULT_MAX_DEPTH, DEFAULT_MAX_SIZE, MAX_SIZE, Document, Kind, Limits, parse
from .error import JsonError
from .ryu import format_float, write_float
from .writer import Writer
