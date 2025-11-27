from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, Optional


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
    ) -> Path:
        """
        Execute the bundled Ghidra script against `binary_path`.

        Returns the path to the JSON output produced by the script.
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

        json_output = raw_dir / "analysis.json"
        script_path = self.script_dir.resolve()
        script_file = script_path / self.script_name
        if not script_file.exists():
            raise FileNotFoundError(f"Ghidra script missing: {script_file}")

        env = os.environ.copy()
        env["LAZARUS_OUTPUT_JSON"] = str(json_output)

        cmd = [
            str(self.analyze_headless),
            str(project_dir),
            project_name,
            "-import",
            str(binary_path),
            "-overwrite",
            "-scriptPath",
            str(script_path),
            "-postScript",
            self.script_name,
        ]

        log_file = raw_dir / "ghidra.log"
        with open(log_file, "w", encoding="utf-8") as log_handle:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
            )
            for line in process.stdout:  # type: ignore[attr-defined]
                log_handle.write(line)
                if log_callback:
                    log_callback(line.rstrip())
            ret = process.wait()

        if ret != 0:
            raise GhidraRunnerError(
                f"Ghidra analyzeHeadless failed with exit code {ret}. "
                f"See {log_file} for details."
            )

        if not json_output.exists():
            raise GhidraRunnerError(
                "Ghidra script completed without producing analysis.json"
            )

        return json_output

