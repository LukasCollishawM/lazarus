from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

PROCESS_CREATE_THREAD = 0x0002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_RIGHTS = (
    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF

TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x08
SE_PRIVILEGE_ENABLED = 0x02


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


def enable_debug_privilege() -> bool:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        if not advapi32.AdjustTokenPrivileges(
            token, False, ctypes.byref(privileges), ctypes.sizeof(privileges), None, None
        ):
            return False
        return ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(token)


def inject_dll(pid: int, dll_path: Path) -> int:
    dll_path = Path(dll_path).resolve()
    if not dll_path.is_file():
        raise FileNotFoundError(f"DLL not found: {dll_path}")

    process = kernel32.OpenProcess(PROCESS_RIGHTS, False, pid)
    if not process:
        _raise_last_error("OpenProcess failed")
    try:
        size = (len(str(dll_path)) + 1) * ctypes.sizeof(wintypes.WCHAR)
        remote_mem = kernel32.VirtualAllocEx(process, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            _raise_last_error("VirtualAllocEx failed")
        try:
            buffer = ctypes.create_unicode_buffer(str(dll_path))
            if not kernel32.WriteProcessMemory(process, remote_mem, buffer, size, None):
                _raise_last_error("WriteProcessMemory failed")
            kernel_handle = kernel32.GetModuleHandleW("kernel32.dll")
            if not kernel_handle:
                _raise_last_error("GetModuleHandleW failed")
            load_library = kernel32.GetProcAddress(kernel_handle, b"LoadLibraryW")
            if not load_library:
                _raise_last_error("GetProcAddress failed")
            thread = kernel32.CreateRemoteThread(process, None, 0, load_library, remote_mem, 0, None)
            if not thread:
                _raise_last_error("CreateRemoteThread failed")
            try:
                kernel32.WaitForSingleObject(thread, INFINITE)
                exit_code = wintypes.DWORD()
                if not kernel32.GetExitCodeThread(thread, ctypes.byref(exit_code)):
                    _raise_last_error("GetExitCodeThread failed")
                if exit_code.value == 0:
                    raise OSError("Remote LoadLibraryW returned 0")
                return exit_code.value
            finally:
                kernel32.CloseHandle(thread)
        finally:
            kernel32.VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)
    finally:
        kernel32.CloseHandle(process)


def _raise_last_error(message: str) -> None:
    err = ctypes.get_last_error()
    raise OSError(err, f"{message}: {err}")



