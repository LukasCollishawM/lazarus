from __future__ import annotations

import json
from dataclasses import dataclass, field
import re
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
    notes: List[str] = field(default_factory=list)
    struct_hints: List[Dict[str, object]] = field(default_factory=list)
    payload_hints: List[Dict[str, object]] = field(default_factory=list)
    request_response_hints: List[Dict[str, object]] = field(default_factory=list)
    string_tables: List[Dict[str, object]] = field(default_factory=list)
    enum_candidates: List[Dict[str, object]] = field(default_factory=list)
    auth_hints: List[Dict[str, object]] = field(default_factory=list)

    def network_functions(self) -> List[DiscoveredFunction]:
        return [fn for fn in self.functions if fn.is_likely_network()]

    def abi_hints(self) -> List[Dict[str, object]]:
        hints: List[Dict[str, object]] = []
        for fn in self.functions:
            ptr_ops = fn.summary.get("pointerOps", 0)
            array_ops = fn.summary.get("arrayAccesses", 0)
            if ptr_ops + array_ops >= 5:
                hints.append(
                    {
                        "function": fn.name,
                        "entryPoint": fn.entry_point,
                        "pointerOps": ptr_ops,
                        "arrayOps": array_ops,
                        "note": "High pointer/array usage; likely interacts with structured memory.",
                    }
                )
        return hints

    def inferred_payload_fields(self) -> List[Dict[str, object]]:
        aggregated: Dict[str, Dict[str, object]] = {}

        def merge_children(
            target: Dict[str, Dict[str, object]], child_data: Dict[str, object], confidence: float
        ) -> None:
            name = child_data.get("name")
            if not name:
                return
            node = target.setdefault(
                name,
                {
                    "name": name,
                    "score": 0.0,
                    "typeScores": {},
                    "children": {},
                },
            )
            node["score"] += confidence
            type_hint = child_data.get("type") or child_data.get("typeHint")
            if isinstance(type_hint, str) and type_hint:
                scores = node.setdefault("typeScores", {})
                scores[type_hint] = scores.get(type_hint, 0.0) + confidence
            for grand in child_data.get("children", []):
                merge_children(node.setdefault("children", {}), grand, confidence * 0.9)

        def finalize_children(child_map: Dict[str, Dict[str, object]]) -> List[Dict[str, object]]:
            children: List[Dict[str, object]] = []
            for value in child_map.values():
                type_hint = None
                type_scores = value.get("typeScores", {})
                if isinstance(type_scores, dict) and type_scores:
                    type_hint = max(type_scores.items(), key=lambda item: item[1])[0]
                children.append(
                    {
                        "name": value["name"],
                        "score": round(value["score"], 2),
                        "typeHint": type_hint,
                        "children": finalize_children(value.get("children", {})),
                    }
                )
            children.sort(key=lambda item: (-item["score"], item["name"]))
            return children[:16]

        for hint in self.payload_hints:
            function_name = hint.get("function", "")
            for key in hint.get("keys", []):
                name = key.get("name")
                if not name:
                    continue
                confidence = float(key.get("confidence", 0.5))
                entry = aggregated.setdefault(
                    name,
                    {
                        "name": name,
                        "score": 0.0,
                        "sources": set(),
                        "examples": [],
                        "typeScores": {},
                        "children_map": {},
                    },
                )
                entry["score"] += confidence
                if function_name:
                    entry["sources"].add(function_name)
                type_hint = key.get("type")
                if isinstance(type_hint, str) and type_hint:
                    scores = entry.setdefault("typeScores", {})
                    scores[type_hint] = scores.get(type_hint, 0.0) + confidence
                source_text = key.get("source")
                if source_text and len(entry["examples"]) < 3:
                    entry["examples"].append(source_text)
                for child in key.get("children", []):
                    merge_children(entry["children_map"], child, confidence)
        candidates: List[Dict[str, object]] = []
        for value in aggregated.values():
            type_hint = None
            type_scores = value.get("typeScores", {})
            if isinstance(type_scores, dict) and type_scores:
                type_hint = max(type_scores.items(), key=lambda item: item[1])[0]
            candidates.append(
                {
                    "name": value["name"],
                    "score": round(value["score"], 2),
                    "sources": sorted(value["sources"]),
                    "examples": value["examples"],
                    "typeHint": type_hint,
                    "children": finalize_children(value.get("children_map", {})),
                }
            )
        candidates.sort(key=lambda item: (-item["score"], item["name"]))
        return candidates[:32]

    def function_payload_links(
        self, inferred_fields: List[Dict[str, object]]
    ) -> List[Dict[str, object]]:
        field_names = {field.get("name", "") for field in inferred_fields if field.get("name")}
        if not field_names:
            return []
        token_re = re.compile(r'"([A-Za-z0-9_]{3,64})"')
        links: Dict[str, Dict[str, object]] = {}
        for hint in self.request_response_hints:
            function = hint.get("function", "")
            entry = hint.get("entryPoint", "")
            source = hint.get("source", "") or ""
            tokens = set(token_re.findall(source))
            matched = sorted(field_names.intersection(tokens))
            if not matched:
                continue
            key = f"{function}@{entry}"
            record = links.setdefault(
                key,
                {
                    "function": function,
                    "entryPoint": entry,
                    "httpVerbs": set(),
                    "endpoints": set(),
                    "matchedFields": set(),
                    "confidence": 0.0,
                },
            )
            for verb in hint.get("httpVerbs", []):
                record["httpVerbs"].add(verb)
            for endpoint in hint.get("endpointStrings", []):
                record["endpoints"].add(endpoint)
            record["matchedFields"].update(matched)
            record["confidence"] = max(
                record["confidence"], float(hint.get("confidence", 0.3))
            )
        output = []
        for record in links.values():
            output.append(
                {
                    "function": record["function"],
                    "entryPoint": record["entryPoint"],
                    "httpVerbs": sorted(record["httpVerbs"]),
                    "endpoints": sorted(record["endpoints"]),
                    "payloadFields": sorted(record["matchedFields"]),
                    "confidence": round(record["confidence"], 2),
                }
            )
        output.sort(key=lambda item: (-item["confidence"], item["function"]))
        return output[:20]


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
        notes=payload.get("notes", []),
        struct_hints=payload.get("structHints", []),
        payload_hints=payload.get("payloadHints", []),
        request_response_hints=payload.get("requestResponseHints", []),
        string_tables=payload.get("stringTables", []),
        enum_candidates=payload.get("enumCandidates", []),
        auth_hints=payload.get("authHints", []),
    )

