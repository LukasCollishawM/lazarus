from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .parser import AnalysisReport


def build_clean_report(raw: AnalysisReport) -> Dict[str, object]:
    network_functions = []
    for fn in raw.network_functions():
        network_functions.append(
            {
                "name": fn.name,
                "entryPoint": fn.entry_point,
                "imports": fn.import_hits,
                "patterns": fn.prologue_patterns[:2],
                "summary": fn.summary,
            }
        )

    return {
        "meta": raw.meta,
        "networkFunctions": network_functions,
        "pointerPatterns": raw.pointer_patterns,
        "stringReferences": raw.string_refs,
    }


def write_clean_report(report: Dict[str, object], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)

