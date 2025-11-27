# -*- coding: utf-8 -*-
# request_response_json.py
# Extracts heuristic request/response metadata, enums, and string tables.
#@category Lazarus

import json
import os
import time

from ghidra.program.model.listing import Function

OUTPUT_FILE = os.environ.get(
    "LAZARUS_OUTPUT_JSON",
    os.path.join(os.environ.get("TEMP", "."), "lazarus_request_response.json"),
)

HTTP_VERBS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
RESPONSE_HINTS = ["HTTP/1", "Status", "success", "error", "OK", "FAILED"]
ENDPOINT_DELIMS = ["/", "api", "contract", "leaderboard", "match", "mission"]
AUTH_KEYWORDS = ["AUTH", "TOKEN", "BEARER", "SESSION", "APIKEY", "SIGNATURE"]

MIN_TABLE_SIZE = 3
MAX_TABLE_SIZE = 64


def collect_request_response():
    hints = []
    auth_hints = []
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    string_refs = []
    while data_iter.hasNext():
        datum = data_iter.next()
        if datum is None:
            continue
        try:
            value = datum.getValue()
            if value is None:
                continue
            text = str(value)
        except Exception:
            continue
        if not text:
            continue
        upper = text.upper()
        matches = []
        for verb in HTTP_VERBS:
            if verb in upper:
                matches.append(verb)
        endpoint_hits = [d for d in ENDPOINT_DELIMS if d.lower() in text.lower()]
        auth_matches = [kw for kw in AUTH_KEYWORDS if kw in upper]
        if matches or endpoint_hits:
            refs = currentProgram.getReferenceManager().getReferencesTo(datum.getMinAddress())
            functions = set()
            for ref in refs:
                fn = get_function_for_address(ref.getFromAddress())
                if fn:
                    functions.add(fn)
            for fn in functions:
                hints.append(
                    {
                        "function": fn.getName(),
                        "entryPoint": str(fn.getEntryPoint()),
                        "httpVerbs": matches,
                        "endpointStrings": [text] if endpoint_hits else [],
                        "confidence": min(1.0, 0.3 * len(matches) + 0.2 * len(endpoint_hits)),
                        "source": text,
                    }
                )
        if auth_matches:
            refs = currentProgram.getReferenceManager().getReferencesTo(datum.getMinAddress())
            functions = set()
            for ref in refs:
                fn = get_function_for_address(ref.getFromAddress())
                if fn:
                    functions.add(fn)
            for fn in functions:
                auth_hints.append(
                    {
                        "function": fn.getName(),
                        "entryPoint": str(fn.getEntryPoint()),
                        "keywords": auth_matches,
                        "headerSample": text,
                        "confidence": min(1.0, 0.4 + 0.1 * len(auth_matches)),
                    }
                )
    return hints, auth_hints


def collect_string_tables():
    tables = []
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    visited = set()
    while data_iter.hasNext():
        datum = data_iter.next()
        if datum is None:
            continue
        start_addr = datum.getMinAddress()
        if start_addr in visited:
            continue
        if not datum.getDataType().getName().lower().startswith("pointer"):
            continue
        table_strings = []
        cursor = datum
        while cursor:
            visited.add(cursor.getMinAddress())
            ptr_value = cursor.getValue()
            if ptr_value is None:
                break
            str_data = listing.getDataAt(ptr_value)
            if str_data is None:
                break
            try:
                text = str(str_data.getValue())
            except Exception:
                break
            if not text:
                break
            table_strings.append(text)
            next_addr = cursor.getMaxAddress().add(1)
            cursor = listing.getDefinedDataAt(next_addr)
            if cursor is None:
                break
            if not cursor.getDataType().getName().lower().startswith("pointer"):
                break
            if len(table_strings) >= MAX_TABLE_SIZE:
                break
        if MIN_TABLE_SIZE <= len(table_strings) <= MAX_TABLE_SIZE:
            symbol = currentProgram.getSymbolTable().getPrimarySymbol(start_addr)
            name = symbol.getName() if symbol else "STRING_TABLE"
            tables.append(
                {
                    "label": name,
                    "address": str(start_addr),
                    "strings": table_strings,
                    "confidence": min(1.0, 0.2 + 0.05 * len(table_strings)),
                }
            )
    return tables


def collect_enum_candidates():
    enums = []
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        datum = data_iter.next()
        if datum is None:
            continue
        dt_name = datum.getDataType().getName().lower()
        if "enum" in dt_name:
            values = []
            component_iter = datum.getComponent(0)
            if component_iter:
                values.append(str(component_iter))
            try:
                raw = datum.getValue()
                if raw is not None:
                    values.append(str(raw))
            except Exception:
                pass
            if values:
                enums.append(
                    {
                        "label": datum.getDataType().getName(),
                        "address": str(datum.getMinAddress()),
                        "values": values,
                        "confidence": 0.8,
                    }
                )
    return enums


def get_function_for_address(addr):
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionContaining(addr)


def main():
    request_response, auth_hints = collect_request_response()
    payload = {
        "meta": {"program": currentProgram.getName(), "timestamp": int(time.time())},
        "requestResponseHints": request_response,
        "stringTables": collect_string_tables(),
        "enumCandidates": collect_enum_candidates(),
        "authHints": auth_hints,
    }
    parent = os.path.dirname(OUTPUT_FILE)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)
    with open(OUTPUT_FILE, "w") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    println("Request/response hints written to {}".format(OUTPUT_FILE))


if __name__ == "__main__":
    main()


