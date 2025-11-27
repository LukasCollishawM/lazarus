# -*- coding: utf-8 -*-
# network_patterns_json.py
# Emits a machine-readable JSON report of network-adjacent patterns.
#@category Lazarus

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit, Function

import json
import os
import time

OUTPUT_FILE = os.environ.get(
    "LAZARUS_OUTPUT_JSON",
    os.path.join(os.environ.get("TEMP", "."), "lazarus_analysis_report.json"),
)

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

NETWORK_KEYWORDS = [
    "contracts",
    "http",
    "https",
    "api",
    "leaderboard",
    "matchmaking",
    "session",
    "search",
    "upload",
    "download",
    "network",
    "endpoint",
    "plantera",
]


def get_function_by_address(addr):
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionContaining(toAddr(addr))


def get_function_for_address(addr):
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionContaining(addr)


def get_instruction_bytes(addr, count):
    listing = currentProgram.getListing()
    bytes_out = []
    current = addr
    while len(bytes_out) < count:
        cu = listing.getCodeUnitAt(current)
        if cu is None:
            break
        for b in cu.getBytes():
            bytes_out.append(b & 0xFF)
            if len(bytes_out) >= count:
                break
        current = current.add(1)
    return bytes_out


def bytes_to_pattern(bytes_list, mask):
    parts = []
    for idx, b in enumerate(bytes_list):
        if idx < len(mask) and not mask[idx]:
            parts.append("??")
        else:
            parts.append("{:02X}".format(b))
    return " ".join(parts)


def is_rip_relative_load(inst_bytes, offset):
    if offset + 6 >= len(inst_bytes):
        return False
    b0 = inst_bytes[offset]
    b1 = inst_bytes[offset + 1]
    b2 = inst_bytes[offset + 2]
    if b0 == 0x48 and b1 == 0x8B and b2 == 0x05:
        return True
    if b0 == 0x48 and b1 == 0x8D and b2 == 0x05:
        return True
    return False


def analyze_function(fn):
    result = {
        "name": fn.getName(),
        "entryPoint": str(fn.getEntryPoint()),
        "prologuePatterns": [],
        "ripLoads": [],
        "imports": [],
        "summary": {},
    }

    body = fn.getBody()
    if body is None:
        result["summary"]["note"] = "No body"
        return result

    inst_bytes = get_instruction_bytes(fn.getEntryPoint(), 3000)
    result["summary"]["byteSample"] = len(inst_bytes)

    rip_candidates = []
    for idx in range(len(inst_bytes) - 6):
        if is_rip_relative_load(inst_bytes, idx):
            start = max(0, idx - 2)
            end = min(len(inst_bytes), idx + 14)
            window = inst_bytes[start:end]
            mask = [True] * len(window)
            offset_in_window = idx - start + 3
            for j in range(4):
                if offset_in_window + j < len(mask):
                    mask[offset_in_window + j] = False
            pattern = bytes_to_pattern(window, mask)
            rip_candidates.append(
                {
                    "offset": idx,
                    "pattern": pattern,
                }
            )

    rip_candidates.sort(key=lambda item: len(item["pattern"].split()), reverse=True)
    result["ripLoads"] = rip_candidates[:10]
    if rip_candidates:
        result["prologuePatterns"].append(rip_candidates[0]["pattern"])

    called_imports = []
    try:
        called = fn.getCalledFunctions(monitor)
        it = called.iterator()
        while it.hasNext():
            target = it.next()
            if target is None:
                continue
            if target.isExternal():
                called_imports.append(target.getName())
    except Exception:
        pass
    result["imports"] = sorted(set(called_imports))

    iface = DecompInterface()
    iface.openProgram(currentProgram)
    res = iface.decompileFunction(fn, 30, monitor)
    if res and res.getDecompiledFunction():
        code = res.getDecompiledFunction().getC()
        lines = code.splitlines()
        arrays = len([line for line in lines if "[" in line and "]" in line])
        loops = len(
            [line for line in lines if "for" in line.lower() or "while" in line.lower()]
        )
        ptrs = len([line for line in lines if "*" in line or "->" in line])
        globals_count = len([line for line in lines if "DAT_" in line or "PTR_" in line])
        result["summary"].update(
            {
                "arrayAccesses": arrays,
                "loops": loops,
                "pointerOps": ptrs,
                "globalRefs": globals_count,
            }
        )
    return result


def analyze_strings():
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    ref_manager = currentProgram.getReferenceManager()

    strings_out = []
    while data_iter.hasNext():
        datum = data_iter.next()
        if datum is None:
            continue
        try:
            val = str(datum.getValue())
        except:
            continue
        if not val:
            continue
        lowered = val.lower()
        if not any(needle.lower() in lowered for needle in NETWORK_KEYWORDS):
            continue
        refs = ref_manager.getReferencesTo(datum.getMinAddress())
        funcs = []
        for ref in refs:
            fn = get_function_for_address(ref.getFromAddress())
            if fn and fn.getName() not in funcs:
                funcs.append(fn.getName())
            if len(funcs) >= 5:
                break
        strings_out.append(
            {
                "string": val,
                "address": str(datum.getMinAddress()),
                "referencedBy": funcs,
            }
        )
        if len(strings_out) >= 50:
            break
    return strings_out


def collect_report():
    functions = []
    for addr in KNOWN_FUNCTION_ADDRESSES:
        fn = get_function_by_address(addr)
        if fn is None:
            continue
        functions.append(analyze_function(fn))

    pointer_patterns = []
    for fn_data in functions:
        for candidate in fn_data.get("ripLoads", []):
            pointer_patterns.append(
                {
                    "function": fn_data["name"],
                    "entryPoint": fn_data["entryPoint"],
                    "pattern": candidate["pattern"],
                }
            )

    report = {
        "meta": {
            "program": currentProgram.getName(),
            "timestamp": int(time.time()),
        },
        "functions": functions,
        "pointerPatterns": pointer_patterns[:25],
        "stringReferences": analyze_strings(),
    }
    return report


def main():
    report = collect_report()
    parent = os.path.dirname(OUTPUT_FILE)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)
    with open(OUTPUT_FILE, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    println("Lazarus JSON report written to {}".format(OUTPUT_FILE))


if __name__ == "__main__":
    main()

