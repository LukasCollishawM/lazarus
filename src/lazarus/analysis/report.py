from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List

from .parser import AnalysisReport

PAYLOAD_SCHEMA_VERSION = 2
REQUEST_VERBS = {"POST", "PUT", "PATCH", "DELETE"}
RESPONSE_VERBS = {"GET", "HEAD", "OPTIONS"}


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

    inferred_fields = raw.inferred_payload_fields()
    return {
        "meta": raw.meta,
        "networkFunctions": network_functions,
        "pointerPatterns": raw.pointer_patterns,
        "stringReferences": raw.string_refs,
        "abiHints": raw.struct_hints or raw.abi_hints(),
        "notes": raw.notes,
        "payloadHints": raw.payload_hints,
        "inferredPayloadFields": inferred_fields,
        "requestResponseHints": raw.request_response_hints,
        "stringTables": raw.string_tables,
        "enumCandidates": raw.enum_candidates,
        "functionPayloadLinks": raw.function_payload_links(inferred_fields),
        "authHints": raw.auth_hints,
        "payloadSchemaVersions": {
            "canonical": raw.meta.get("schemaVersion", 1),
            "payloadSchema": PAYLOAD_SCHEMA_VERSION,
            "requestPayload": PAYLOAD_SCHEMA_VERSION,
            "responsePayload": PAYLOAD_SCHEMA_VERSION,
        },
    }


def write_clean_report(report: Dict[str, object], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)


def write_payload_schema(report: Dict[str, object], output_path: Path) -> None:
    fields = report.get("inferredPayloadFields", [])
    function_links = report.get("functionPayloadLinks", [])
    categorized = _categorize_fields_by_direction(fields, function_links)
    payload = {
        "schemaVersion": PAYLOAD_SCHEMA_VERSION,
        "generatedAt": int(time.time()),
        "request": {
            "fieldCount": len(categorized["request"]),
            "fields": categorized["request"],
        },
        "response": {
            "fieldCount": len(categorized["response"]),
            "fields": categorized["response"],
        },
        "allFields": categorized["all"],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def _categorize_fields_by_direction(
    fields: List[Dict[str, object]], links: List[Dict[str, object]]
) -> Dict[str, List[Dict[str, object]]]:
    function_directions: Dict[str, set] = {}
    for link in links or []:
        fn = link.get("function")
        if not fn:
            continue
        verbs = {verb.upper() for verb in link.get("httpVerbs", [])}
        directions: set = set()
        if verbs.intersection(RESPONSE_VERBS):
            directions.add("response")
        if verbs.intersection(REQUEST_VERBS) or not directions:
            directions.add("request")
        entry = function_directions.setdefault(fn, set())
        entry.update(directions)

    request_fields: List[Dict[str, object]] = []
    response_fields: List[Dict[str, object]] = []
    all_fields: List[Dict[str, object]] = []

    for field in fields or []:
        directions: set = set()
        for source in field.get("sources", []):
            directions.update(function_directions.get(source, []))
        if not directions:
            directions = {"request", "response"}
        entry = dict(field)
        entry["directions"] = sorted(directions)
        all_fields.append(entry)
        if "request" in directions:
            request_fields.append(dict(entry))
        if "response" in directions:
            response_fields.append(dict(entry))

    return {
        "request": request_fields[:32],
        "response": response_fields[:32],
        "all": all_fields[:64],
    }

