from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional


class GhidraRunnerError(RuntimeError):
    """Raised when headless Ghidra execution fails."""


class GhidraRunner:
    """Thin wrapper around Ghidra's analyzeHeadless utility."""

    def __init__(
        self,
        ghidra_install: Optional[Path] = None,
        script_name: str = "network_patterns_json.py",
    ) -> None:
        self.ghidra_install = self._resolve_install(ghidra_install)
        self.analyze_headless = self._resolve_analyze_headless(self.ghidra_install)
        self.script_dir = Path(__file__).parent / "scripts"
        self.script_name = script_name

    def _resolve_install(self, override: Optional[Path]) -> Path:
        if override:
            install = Path(override).expanduser()
            if not install.exists():
                raise FileNotFoundError(f"Ghidra install not found: {install}")
            return install

        env_path = os.getenv("GHIDRA_INSTALL_DIR")
        if env_path:
            install = Path(env_path)
            if install.exists():
                return install

        # Try a few common Windows locations
        candidates = [
            Path("C:/Program Files/Ghidra"),
            Path("C:/Program Files (x86)/Ghidra"),
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate

        raise FileNotFoundError(
            "Unable to locate Ghidra installation. "
            "Set GHIDRA_INSTALL_DIR or pass --ghidra explicitly."
        )

    def _resolve_analyze_headless(self, install: Path) -> Path:
        if os.name == "nt":
            script = install / "support" / "analyzeHeadless.bat"
        else:
            script = install / "support" / "analyzeHeadless"

        if not script.exists():
            raise FileNotFoundError(f"analyzeHeadless not found at {script}")
        return script

    def run_analysis(
        self,
        binary_path: Path,
        output_dir: Path,
        *,
        project_name: str = "lazarus_project",
        log_callback: Optional[Callable[[str], None]] = None,
        env_overrides: Optional[Dict[str, str]] = None,
        scripts: Optional[List[str]] = None,
    ) -> Path:
        """
        Execute one or more Ghidra scripts against `binary_path`.

        Returns the path to the combined JSON output.
        """
        binary_path = Path(binary_path).expanduser()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        output_dir = Path(output_dir).expanduser()
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_dir = output_dir / "raw"
        raw_dir.mkdir(exist_ok=True)

        project_dir = raw_dir / "ghidra_project"
        project_dir.mkdir(exist_ok=True)

        script_list = scripts or [self.script_name]
        script_path = self.script_dir.resolve()
        combined: Dict[str, object] = {}

        for idx, script in enumerate(script_list):
            temp_output = raw_dir / f"{Path(script).stem}.json"
            env = os.environ.copy()
            env["LAZARUS_OUTPUT_JSON"] = str(temp_output)
            if env_overrides:
                env.update(env_overrides)

            # Build command - ensure all paths are absolute
            # We'll convert to short paths inside the log context
            analyze_headless_path = str(self.analyze_headless.resolve())
            project_dir_path = str(project_dir.resolve())
            binary_path_str = str(binary_path.resolve())
            script_path_str = str(script_path.resolve())

            log_file = raw_dir / f"ghidra_{Path(script).stem}.log"
            with open(log_file, "w", encoding="utf-8") as log_handle:
                def get_short_path(long_path: Path) -> str:
                    """Get Windows short path (8.3 format) to avoid spaces and special characters."""
                    if os.name != "nt":
                        return str(long_path.resolve())
                    long_str = str(long_path.resolve())
                    try:
                        # Use PowerShell to get short path - suppress welcome message with -NoProfile
                        # Need to escape single quotes and backslashes in path
                        escaped_path = long_str.replace("'", "''").replace("\\", "\\\\")
                        ps_cmd = f"(New-Object -ComObject Scripting.FileSystemObject).GetFile([System.IO.Path]::GetFullPath('{escaped_path}')).ShortPath"
                        result = subprocess.run(
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                            capture_output=True,
                            text=True,
                            timeout=5,
                            check=False,
                        )
                        if result.returncode == 0:
                            # Extract just the path from output (may have extra text)
                            output_lines = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                            # Find the line that looks like a path (starts with drive letter)
                            for line in reversed(output_lines):  # Check from end (most likely to be the path)
                                if len(line) > 2 and line[1] == ':' and Path(line).exists():
                                    short = line.strip().strip('"').strip("'")
                                    log_handle.write(f"Short path for {long_str}: {short}\n")
                                    return short
                            log_handle.write(f"Could not find valid short path in output: {result.stdout}\n")
                        else:
                            log_handle.write(f"PowerShell short path failed (code {result.returncode}): {result.stderr}\n")
                    except Exception as e:
                        log_handle.write(f"Exception getting short path: {e}\n")
                    # Fallback to original path
                    log_handle.write(f"Using original path: {long_str}\n")
                    return long_str
                
                # Convert to short paths if on Windows
                if os.name == "nt":
                    analyze_headless_path = get_short_path(self.analyze_headless)
                    project_dir_path = get_short_path(project_dir)
                    binary_path_str = get_short_path(binary_path)
                    script_path_str = get_short_path(script_path)
                
                # Build command list - Python's subprocess handles quoting automatically
                cmd = [
                    analyze_headless_path,
                    project_dir_path,
                    f"{project_name}_{idx}",
                    "-import",
                    binary_path_str,
                    "-overwrite",
                    "-scriptPath",
                    script_path_str,
                    "-postScript",
                    script,
                ]
                
                # Log the command for debugging
                log_handle.write(f"Command parts: {cmd}\n")
                log_handle.flush()
                
                # On Windows, batch files have issues with paths containing spaces and parentheses
                # The batch file uses %1, %2, etc. which don't preserve quotes properly
                # Solution: Use 'call' to invoke the batch file, which preserves quotes better
                if os.name == "nt":
                    # Build command with 'call' prefix to properly handle quoted arguments
                    # 'call' ensures the batch file receives arguments with quotes preserved
                    cmd_with_call = ["call"] + cmd
                    cmd_line = subprocess.list2cmdline(cmd_with_call)
                    log_handle.write(f"Command line: cmd.exe /c {cmd_line}\n")
                    log_handle.flush()
                    # Use cmd.exe /c with 'call' prefix
                    process = subprocess.Popen(
                        ["cmd.exe", "/c", cmd_line],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        env=env,
                        text=True,
                        shell=False,
                    )
                else:
                    # On Unix, call directly
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        env=env,
                        text=True,
                        shell=False,
                    )
                for line in process.stdout:  # type: ignore[attr-defined]
                    log_handle.write(line)
                    if log_callback:
                        log_callback(f"{script}: {line.rstrip()}")
                ret = process.wait()

            if ret != 0:
                raise GhidraRunnerError(
                    f"Ghidra analyzeHeadless failed for {script} (exit {ret}). "
                    f"See {log_file} for details."
                )

            if not temp_output.exists():
                raise GhidraRunnerError(f"{script} did not produce JSON output")

            with open(temp_output, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            combined = self._merge_outputs(combined, data, idx == 0)

        json_output = raw_dir / "analysis.json"
        with open(json_output, "w", encoding="utf-8") as handle:
            json.dump(combined, handle, indent=2)
        return json_output

    def _merge_outputs(
        self, base: Dict[str, object], new: Dict[str, object], replace: bool
    ) -> Dict[str, object]:
        if replace or not base:
            return new
        for key, value in new.items():
            if key in {
                "functions",
                "pointerPatterns",
                "stringReferences",
                "notes",
                "structHints",
                "payloadHints",
                "requestResponseHints",
                "stringTables",
                "enumCandidates",
            }:
                base.setdefault(key, [])
                base[key].extend(value)
            elif key == "meta":
                base.setdefault("meta", {}).update(value)
            else:
                base[key] = value
        return base

