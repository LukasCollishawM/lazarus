# -*- coding: utf-8 -*-
# payload_hints_json.py
# Emits heuristic payload field hints by scanning string references.
#@category Lazarus

from ghidra.program.model.listing import Function

import json
import os
import re
import time

OUTPUT_FILE = os.environ.get(
    "LAZARUS_PAYLOAD_HINTS_JSON",
    os.path.join(os.environ.get("TEMP", "."), "lazarus_payload_hints.json"),
)


def _parse_address_list(value):
    addresses = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            addresses.append(int(part, 0))
        except ValueError:
            continue
    return addresses


KNOWN_FUNCTION_ADDRESSES = [
    0x004e2770,
    0x0051c9f0,
    0x0052c360,
    0x00535780,
    0x006bd230,
    0x00893270,
    0x008ab820,
    0x0090a2d0,
]

KEY_PATTERN = re.compile(r'"([A-Za-z0-9_]{3,64})"\s*:')
TOKEN_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,63}$")
NUMBER_LITERAL = re.compile(r"^[+-]?\d+(\.\d+)?$")
MAX_CHILDREN = 16
MAX_DEPTH = 2


def get_function_by_address(addr: int) -> Function:
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionContaining(toAddr(addr))


def extract_keys_from_string(value: str):
    hints = []
    for match in KEY_PATTERN.finditer(value):
        segment = value[match.end() :]
        value_slice = _extract_value_slice(segment)
        type_hint = infer_type_from_slice(value_slice)
        children = []
        if type_hint == "object":
            children = extract_children(value_slice, depth=0)
        elif type_hint == "array":
            children = extract_array_children(value_slice, depth=0)
        hints.append(
            {
                "name": match.group(1),
                "confidence": 0.9,
                "source": _truncate(value),
                "type": type_hint,
                "children": children,
            }
        )
    if hints:
        return hints

    cleaned = value.strip().strip("{}[]'\"")
    if TOKEN_PATTERN.match(cleaned):
        hints.append(
            {"name": cleaned, "confidence": 0.5, "source": _truncate(value), "type": "string"}
        )
    return hints


def _truncate(value: str) -> str:
    sanitized = value.replace("\n", "\\n")
    if len(sanitized) > 96:
        return sanitized[:93] + "..."
    return sanitized


def _extract_value_slice(segment: str) -> str:
    temp = segment.lstrip()
    if temp.startswith(":"):
        temp = temp[1:].lstrip()
    buffer = []
    depth = 0
    in_string = False
    escape = False
    for char in temp:
        buffer.append(char)
        if char == "\\" and not escape:
            escape = True
            continue
        if char == '"' and not escape:
            in_string = not in_string
        escape = False
        if in_string:
            continue
        if char in "{[":
            depth += 1
        elif char in "}]":
            if depth > 0:
                depth -= 1
        elif char == "," and depth == 0:
            buffer.pop()  # remove comma
            break
        elif char == "}" and depth == 0:
            break
        if not in_string and depth == 0 and char in "\r\n":
            break
        if not in_string and depth == 0 and len(buffer) > 120:
            break
    return "".join(buffer).strip()


def infer_type_from_slice(value_slice: str) -> str:
    if not value_slice:
        return "string"
    lowered = value_slice.lower()
    if lowered.startswith('"'):
        if "%d" in lowered or "%i" in lowered or "%u" in lowered:
            return "number"
        if "%f" in lowered or "%g" in lowered:
            return "number"
        return "string"
    if any(token in lowered for token in ("%d", "%i", "%u", "%f", "%g")):
        return "number"
    if lowered.startswith("true") or lowered.startswith("false"):
        return "boolean"
    if lowered.startswith("{"):
        return "object"
    if lowered.startswith("["):
        return "array"
    if NUMBER_LITERAL.match(lowered):
        return "number"
    if lowered.startswith("'") and lowered.endswith("'"):
        return "string"
    return "string"


def extract_children(value_slice: str, depth: int) -> list:
    if depth >= MAX_DEPTH:
        return []
    children = []
    for match in KEY_PATTERN.finditer(value_slice):
        segment = value_slice[match.end() :]
        child_slice = _extract_value_slice(segment)
        child_type = infer_type_from_slice(child_slice)
        child_entry = {
            "name": match.group(1),
            "type": child_type,
        }
        if child_type == "object":
            child_entry["children"] = extract_children(child_slice, depth + 1)
        elif child_type == "array":
            child_entry["children"] = extract_array_children(child_slice, depth + 1)
        children.append(child_entry)
        if len(children) >= MAX_CHILDREN:
            break
    return children


def extract_array_children(value_slice: str, depth: int) -> list:
    # Attempt to inspect first element of array for structural hints
    stripped = value_slice.lstrip()
    if not stripped.startswith("["):
        return []
    inner = stripped[1:].lstrip()
    if not inner:
        return []
    if inner[0] == "{":
        brace_depth = 0
        buf = []
        for char in inner:
            buf.append(char)
            if char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    break
        object_text = "".join(buf)
        element_children = extract_children(object_text, depth + 1)
        return [{"name": "element", "type": "object", "children": element_children}]
    else:
        element_slice = _extract_value_slice(inner)
        element_type = infer_type_from_slice(element_slice)
        return [{"name": "element", "type": element_type}]


def collect_strings(fn: Function):
    listing = currentProgram.getListing()
    body = fn.getBody()
    if body is None:
        return []
    inst_iter = listing.getInstructions(body, True)
    seen = set()
    values = []
    while inst_iter.hasNext():
        inst = inst_iter.next()
        refs = inst.getReferencesFrom()
        if refs is None:
            continue
        for ref in refs:
            if ref is None:
                continue
            ref_type = ref.getReferenceType()
            if ref_type is None or not ref_type.isData():
                continue
            target = ref.getToAddress()
            if target is None or target in seen:
                continue
            seen.add(target)
            data = listing.getDataAt(target)
            if data is None:
                continue
            try:
                value = str(data.getValue())
            except Exception:
                continue
            if value:
                values.append(value)
            if len(values) >= 200:
                return values
    return values


def collect_payload_hints():
    function_env = os.environ.get("LAZARUS_FUNCTION_ADDRS")
    if function_env:
        overrides = _parse_address_list(function_env)
        if overrides:
            KNOWN_FUNCTION_ADDRESSES[:] = overrides

    hints = []
    for addr in KNOWN_FUNCTION_ADDRESSES:
        fn = get_function_by_address(addr)
        if fn is None:
            continue
        keys = {}
        for raw in collect_strings(fn):
            for hint in extract_keys_from_string(raw):
                name = hint["name"]
                existing = keys.get(name)
                if existing is None or hint["confidence"] > existing["confidence"]:
                    keys[name] = hint
                else:
                    if hint.get("type") and not existing.get("type"):
                        existing["type"] = hint["type"]
                    if len(existing.get("examples", [])) < 2:
                        existing.setdefault("examples", []).append(hint["source"])
        if not keys:
            continue
        hints.append(
            {
                "function": fn.getName(),
                "entryPoint": str(fn.getEntryPoint()),
                "keys": sorted(
                    [
                        {
                            "name": name,
                            "confidence": round(data["confidence"], 2),
                            "source": data["source"],
                            "type": data.get("type"),
                        }
                        for name, data in keys.items()
                    ],
                    key=lambda item: (-item["confidence"], item["name"]),
                )[:32],
            }
        )
    return hints


def main():
    payload_hints = collect_payload_hints()
    payload = {
        "meta": {"program": currentProgram.getName(), "timestamp": int(time.time())},
        "payloadHints": payload_hints,
    }
    parent = os.path.dirname(OUTPUT_FILE)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)
    with open(OUTPUT_FILE, "w") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    println("Payload hints written to {}".format(OUTPUT_FILE))


if __name__ == "__main__":
    main()


