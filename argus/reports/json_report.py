"""The JSON report: the report model itself, with a published schema.

The schema is argus/data/report.schema.json. Tools that read ARGUS reports
can check the "schema" field ("argus-report/1") and validate against it.
"""

import json
from pathlib import Path


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def write_json(report: dict, path: Path) -> Path:
    path.write_text(to_json(report), encoding="utf-8")
    return path
