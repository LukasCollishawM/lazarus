from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


NETWORK_IMPORT_PREFIXES = [
    "WinHttp",
    "HttpSendRequest",
    "curl_",
    "URLDownload",
    "Internet",
    "send",
    "recv",
    "WSA",
    "SteamAPI",
]


@dataclass
class DiscoveredFunction:
    name: str
    entry_point: str
    imports: List[str] = field(default_factory=list)
    prologue_patterns: List[str] = field(default_factory=list)
    rip_loads: List[Dict[str, str]] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    @property
    def import_hits(self) -> List[str]:
        hits = []
        for symbol in self.imports:
            for prefix in NETWORK_IMPORT_PREFIXES:
                if symbol.startswith(prefix):
                    hits.append(symbol)
                    break
        return hits

    def is_likely_network(self) -> bool:
        return bool(self.import_hits)


@dataclass
class AnalysisReport:
    meta: Dict[str, object]
    functions: List[DiscoveredFunction]
    pointer_patterns: List[Dict[str, str]]
    string_refs: List[Dict[str, object]]

    def network_functions(self) -> List[DiscoveredFunction]:
        return [fn for fn in self.functions if fn.is_likely_network()]


def load_raw_analysis(path: Path) -> AnalysisReport:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    fns = [
        DiscoveredFunction(
            name=item.get("name", ""),
            entry_point=item.get("entryPoint", ""),
            imports=item.get("imports", []),
            prologue_patterns=item.get("prologuePatterns", []),
            rip_loads=item.get("ripLoads", []),
            summary=item.get("summary", {}),
        )
        for item in payload.get("functions", [])
    ]

    return AnalysisReport(
        meta=payload.get("meta", {}),
        functions=fns,
        pointer_patterns=payload.get("pointerPatterns", []),
        string_refs=payload.get("stringReferences", []),
    )

