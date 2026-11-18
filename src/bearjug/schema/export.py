"""Write the canonical schema as JSON Schema, for non-Python components.

    python -m bearjug.schema.export [output_dir]   # default: ./schema
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import TypeAdapter

from .events import EVENT_ADAPTER
from .evidence import RawEvidence
from .intelligence import INTELLIGENCE_ADAPTER

SCHEMAS: dict[str, TypeAdapter] = {
    "evidence.schema.json": TypeAdapter(RawEvidence),
    "event.schema.json": EVENT_ADAPTER,
    "intelligence.schema.json": INTELLIGENCE_ADAPTER,
}


STRUCTURAL_ONLY = (
    "Generated from bearjug.schema; do not edit. STRUCTURAL ONLY: this JSON "
    "Schema does not encode the cross-field security rules (evidence "
    "sensitivity, production auth policy, experiment labelling, outbound "
    "destinations). Passing it does not mean a record is acceptable. Validate "
    "with bearjug.schema before storing or acting on a record. See docs/schema.md."
)


def render() -> dict[str, str]:
    out = {}
    for name, adapter in SCHEMAS.items():
        schema = {"$comment": STRUCTURAL_ONLY, **adapter.json_schema()}
        out[name] = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    return out


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else Path("schema")
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (out / name).write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
