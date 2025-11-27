# -*- coding: utf-8 -*-
# struct_hints_json.py
# Emits heuristic struct/ABI hints based on pointer-heavy functions.
#@category Lazarus

from ghidra.program.model.listing import Function
from ghidra.app.decompiler import DecompInterface
import json
import os
import time

OUTPUT_FILE = os.environ.get(
    "LAZARUS_STRUCT_HINTS_JSON",
    os.path.join(os.environ.get("TEMP", "."), "lazarus_struct_hints.json"),
)


def is_pointer_heavy(fn: Function) -> bool:
    body = fn.getBody()
    if body is None:
        return False
    count = 0
    instr_iter = currentProgram.getListing().getInstructions(body, True)
    while instr_iter.hasNext():
        instr = instr_iter.next()
        if "PTR" in instr.toString() or "->" in instr.toString():
            count += 1
        if count > 20:
            return True
    return False


def collect_struct_hints():
    hints = []
    iface = DecompInterface()
    iface.openProgram(currentProgram)
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    for fn in funcs:
        if not fn or not fn.getEntryPoint():
            continue
        if not is_pointer_heavy(fn):
            continue
        res = iface.decompileFunction(fn, 30, monitor)
        ptr_ops = 0
        array_ops = 0
        if res and res.getDecompiledFunction():
            code = res.getDecompiledFunction().getC()
            for line in code.splitlines():
                if "*" in line or "->" in line:
                    ptr_ops += 1
                if "[" in line and "]" in line:
                    array_ops += 1
        hints.append(
            {
                "function": fn.getName(),
                "entryPoint": str(fn.getEntryPoint()),
                "pointerOps": ptr_ops,
                "arrayOps": array_ops,
                "note": "Heuristic pointer-heavy function; inspect for structs.",
            }
        )
    return hints[:50]


def main():
    hints = collect_struct_hints()
    payload = {
        "meta": {"program": currentProgram.getName(), "timestamp": int(time.time())},
        "structHints": hints,
    }
    parent = os.path.dirname(OUTPUT_FILE)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)
    with open(OUTPUT_FILE, "w") as handle:
        json.dump(payload, handle, indent=2)
    println("Struct hints written to {}".format(OUTPUT_FILE))


if __name__ == "__main__":
    main()

