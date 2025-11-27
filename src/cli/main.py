from __future__ import annotations

import base64
import binascii
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

try:
    import ed25519  # type: ignore[import]
except ImportError:  # pragma: no cover - optional dependency
    ed25519 = None

import typer
from rich.console import Console
from rich.table import Table

from lazarus.analysis.parser import load_raw_analysis
from lazarus.analysis.report import (
    build_clean_report,
    write_clean_report,
    write_payload_schema,
)
from lazarus.codegen.backend.generator import BackendGenerator
from lazarus.codegen.mod.generator import ModGenerator
from lazarus.ghidra_automation.runner import GhidraRunner, GhidraRunnerError

console = Console()
app = typer.Typer(help="Lazarus meta-tool CLI")
presets_app = typer.Typer(help="Manage configuration presets", invoke_without_command=True)
app.add_typer(presets_app, name="presets")
PRESET_DIR = Path(__file__).resolve().parents[3] / "config"
DEFAULT_PRESET = "hitman.json"
KNOWN_COMMANDS = {"analyze", "presets", "export-schema", "inject", "replay"}


@presets_app.callback()
def presets_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _list_presets()


@presets_app.command("list")
def presets_list() -> None:
    _list_presets()


@presets_app.command("publish")
def presets_publish(
    preset: Path = typer.Argument(..., exists=True, readable=True, help="Preset JSON to sign"),
    private_key: Path = typer.Option(
        ..., "--private-key", "-k", exists=True, readable=True, help="Ed25519 private key file"
    ),
    output: Path = typer.Option(
        PRESET_DIR / "signed", "--output", "-o", help="Directory to write preset + signature"
    ),
) -> None:
    _require_ed25519()
    preset_bytes = preset.read_bytes()
    key_bytes = _read_key_bytes(private_key)
    sk = ed25519.SigningKey(key_bytes)
    signature = sk.sign(preset_bytes)
    output.mkdir(parents=True, exist_ok=True)
    signed_preset = output / preset.name
    signed_preset.write_bytes(preset_bytes)
    sig_path = signed_preset.with_suffix(signed_preset.suffix + ".sig")
    sig_path.write_bytes(signature)
    console.print(f"[green]OK[/] Signed preset written to {signed_preset} (+ {sig_path.name})")


@presets_app.command("verify")
def presets_verify(
    preset: Path = typer.Argument(..., exists=True, readable=True, help="Preset JSON to verify"),
    signature: Path = typer.Option(
        ..., "--signature", "-s", exists=True, readable=True, help=".sig file produced by publish"
    ),
    public_key: Path = typer.Option(
        ..., "--public-key", "-p", exists=True, readable=True, help="Ed25519 public key file"
    ),
) -> None:
    _require_ed25519()
    preset_bytes = preset.read_bytes()
    sig_bytes = signature.read_bytes()
    vk = ed25519.VerifyingKey(_read_key_bytes(public_key))
    try:
        vk.verify(sig_bytes, preset_bytes)
    except ed25519.BadSignatureError:
        console.print("[red]Signature mismatch[/]")
        raise typer.Exit(code=1)
    console.print("[green]OK[/] Signature verified.")


@app.command("export-schema")
def export_schema(
    schema: Path = typer.Argument(..., exists=True, readable=True, help="Path to payload_schema.json"),
    ts_out: Optional[Path] = typer.Option(
        None, "--ts-out", help="Destination for generated payload helper (TypeScript)"
    ),
    cpp_out: Optional[Path] = typer.Option(
        None, "--cpp-out", help="Destination for generated payload header (C++)"
    ),
) -> None:
    """
    Export payload schema JSON into TypeScript and/or C++ helper artifacts.
    """
    with open(schema, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    schema_version = payload.get("schemaVersion", 1)
    fields = _extract_schema_fields(payload)
    if not isinstance(fields, list):
        console.print(f"[red]Invalid schema format inside {schema}[/]")
        raise typer.Exit(code=1)
    if schema_version < 2:
        console.print("[yellow]Warning:[/] legacy payload schema detected (schemaVersion < 2).")
    dummy_report = {
        "meta": {},
        "networkFunctions": [],
        "pointerPatterns": [],
        "stringReferences": [],
        "abiHints": [],
        "notes": [],
        "inferredPayloadFields": fields,
        "functionPayloadLinks": [],
    }
    if ts_out:
        backend_gen = BackendGenerator(dummy_report)
        ts_out.parent.mkdir(parents=True, exist_ok=True)
        backend_gen._write_payload_helpers(ts_out, fields)
        console.print(f"[green]OK[/] TypeScript helper written to {ts_out}")
    if cpp_out:
        mod_gen = ModGenerator(dummy_report)
        cpp_out.parent.mkdir(parents=True, exist_ok=True)
        header_path = cpp_out.with_suffix(".h")
        bridge_header = cpp_out.parent / f"{cpp_out.stem}_bridge.h"
        bridge_source = cpp_out.parent / f"{cpp_out.stem}_bridge.cpp"
        mod_gen._write_payload_schema_header(header_path, fields)
        mod_gen._write_payload_bridge(bridge_header, bridge_source, fields)
        console.print(f"[green]OK[/] C++ helpers written to {header_path}")
    if not ts_out and not cpp_out:
        console.print("[yellow]No output paths provided; nothing was written.[/]")


@app.command("inject")
def inject_command(
    pid: int = typer.Option(..., "--pid", "-p", help="Target Windows process ID"),
    dll: Path = typer.Option(..., "--dll", "-d", exists=True, readable=True, help="Path to generated DLL"),
) -> None:
    """
    Inject a generated DLL into a running Windows process (local-only).
    """
    if sys.platform != "win32":
        console.print("[red]The inject command is only available on Windows.[/]")
        raise typer.Exit(code=1)
    from lazarus.injector.win32 import enable_debug_privilege, inject_dll

    try:
        if enable_debug_privilege():
            console.print("[green]OK[/] SeDebugPrivilege enabled.")
        else:
            console.print("[yellow]Warning:[/] Could not enable SeDebugPrivilege; continuing anyway.")
        inject_dll(pid, dll)
    except Exception as exc:
        console.print(f"[red]Injection failed:[/] {exc}")
        raise typer.Exit(code=1)
    console.print(f"[green]OK[/] Injected {dll} into PID {pid}")


@app.command("replay")
def replay_command(
    recordings: Path = typer.Argument(..., exists=True, readable=True, help="JSON recordings to replay"),
    base_url: str = typer.Option("http://localhost:9000", "--base-url", help="Backend base URL"),
    auth_token: Optional[str] = typer.Option(None, "--auth-token", help="Bearer token to attach"),
    timeout: float = typer.Option(5.0, "--timeout", help="HTTP timeout per request (seconds)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print planned requests without sending"),
) -> None:
    """
    Replay captured HTTP requests against a generated backend.
    """
    from lazarus.replay.runner import replay_requests

    result = replay_requests(
        recordings_path=recordings,
        base_url=base_url,
        auth_token=auth_token,
        timeout=timeout,
        dry_run=dry_run,
    )
    summary = result["summary"]
    console.print(
        f"[green]OK[/] Replay completed: {summary['sent']} sent, "
        f"{summary['success']} succeeded, {summary['failed']} failed."
    )
    if summary["failed"] and result["failures"]:
        table = Table(title="Replay Failures", show_lines=True)
        table.add_column("Index")
        table.add_column("Method")
        table.add_column("Path")
        table.add_column("Status/Error")
        for failure in result["failures"][:10]:
            table.add_row(
                str(failure["index"]),
                failure.get("method", "?"),
                failure.get("path", "?"),
                failure.get("error") or str(failure.get("status")),
            )
        console.print(table)
    if dry_run:
        console.print("[yellow]Dry run only – no HTTP requests were sent.[/]")


def _perform_analyze(
    binary: Path,
    ghidra: Optional[Path],
    output: Path,
    generate_backend: bool,
    generate_mod: bool,
    preset: Optional[str],
    game_config: Optional[Path],
    analysis_json: Optional[Path],
) -> None:
    console.rule("[bold blue]Lazarus Analysis")
    console.print(f"[cyan]Binary:[/] {binary}")
    console.print(f"[cyan]Output:[/] {output}")

    console_logger = RateLimitedConsoleLogger(console)

    config_path = resolve_config_path(preset, game_config)
    if config_path:
        console.print(f"[cyan]Config:[/] {config_path}")

    try:
        result = run_pipeline(
            binary=binary,
            ghidra=ghidra,
            output=output,
            generate_backend=generate_backend,
            generate_mod=generate_mod,
            game_config=config_path,
            log_callback=console_logger,
            analysis_json=analysis_json,
        )
    except (FileNotFoundError, GhidraRunnerError) as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]OK[/] Raw analysis written to {result['raw_json']}")
    console.print(f"[green]OK[/] Clean report written to {result['clean_report']}")
    console.print(f"[green]OK[/] Payload schema written to {result['payload_schema']}")
    if result.get("backend_dir"):
        console.print(f"[green]OK[/] Backend skeleton created at {result['backend_dir']}")
    if result.get("mod_dir"):
        console.print(f"[green]OK[/] Mod skeleton created at {result['mod_dir']}")

    network_fns = result["clean_data"].get("networkFunctions", [])
    table = Table(title="Network Candidates", show_lines=True)
    table.add_column("Function")
    table.add_column("Imports")
    table.add_column("Entry")
    for fn in network_fns[:5]:
        table.add_row(fn["name"], ", ".join(fn["imports"]), fn["entryPoint"])
    console.print(table)

    payload_fields = result["clean_data"].get("inferredPayloadFields", [])
    if payload_fields:
        payload_table = Table(title="Inferred Payload Fields", show_lines=True)
        payload_table.add_column("Field")
        payload_table.add_column("Type")
        payload_table.add_column("Score")
        payload_table.add_column("Sources")
        for field in payload_fields[:10]:
            payload_table.add_row(
                field.get("name", "?"),
                field.get("typeHint", "string") or "string",
                str(field.get("score", 0)),
                ", ".join(field.get("sources", [])),
            )
        console.print(payload_table)

    req_hints = result["clean_data"].get("requestResponseHints", [])
    if req_hints:
        req_table = Table(title="Request/Response Hints", show_lines=True)
        req_table.add_column("Function")
        req_table.add_column("Verbs")
        req_table.add_column("Endpoints")
        req_table.add_column("Confidence")
        for hint in req_hints[:10]:
            req_table.add_row(
                hint.get("function", "?"),
                ", ".join(hint.get("httpVerbs", [])),
                ", ".join(hint.get("endpointStrings", [])),
                f"{hint.get('confidence', 0):.2f}",
            )
        console.print(req_table)

    links = result["clean_data"].get("functionPayloadLinks", [])
    if links:
        link_table = Table(title="Function ↔ Payload Links", show_lines=True)
        link_table.add_column("Function")
        link_table.add_column("Verbs")
        link_table.add_column("Fields")
        link_table.add_column("Confidence")
        for link in links[:10]:
            link_table.add_row(
                link.get("function", "?"),
                ", ".join(link.get("httpVerbs", [])),
                ", ".join(link.get("payloadFields", [])),
                f"{link.get('confidence', 0):.2f}",
            )
        console.print(link_table)

    auth_hints = result["clean_data"].get("authHints", [])
    if auth_hints:
        auth_table = Table(title="Auth / Session Hints", show_lines=True)
        auth_table.add_column("Function")
        auth_table.add_column("Keywords")
        auth_table.add_column("Confidence")
        for hint in auth_hints[:10]:
            auth_table.add_row(
                hint.get("function", "?"),
                ", ".join(hint.get("keywords", [])),
                f"{hint.get('confidence', 0):.2f}",
            )
        console.print(auth_table)

    console.print("[bold green]Done.[/]")


@app.command()
def analyze(
    binary: Path = typer.Argument(..., exists=True, readable=True, help="Game binary path"),
    ghidra: Optional[Path] = typer.Option(
        None, "--ghidra", help="Optional Ghidra install directory (defaults detected automatically)"
    ),
    output: Path = typer.Option(
        Path("./lazarus-output"), "--output", "-o", help="Output directory for reports"
    ),
    generate_backend: bool = typer.Option(
        False, "--generate-backend", help="Emit generated-backend/ skeleton after analysis"
    ),
    generate_mod: bool = typer.Option(
        False, "--generate-mod", help="Emit generated-mod/ skeleton after analysis"
    ),
    preset: Optional[str] = typer.Option(
        None, "--preset", "-p", help="Preset name from config directory (e.g. hitman.json)"
    ),
    game_config: Optional[Path] = typer.Option(
        None, "--game-config", help="Explicit JSON config path (overrides preset)"
    ),
    analysis_json: Optional[Path] = typer.Option(
        None,
        "--analysis-json",
        help="Skip Ghidra and reuse an existing analysis JSON (useful for tests/offline work)",
    ),
):
    """
    Run headless Ghidra analysis and emit cleaned JSON.
    """
    _perform_analyze(
        binary=binary,
        ghidra=ghidra,
        output=output,
        generate_backend=generate_backend,
        generate_mod=generate_mod,
        preset=preset,
        game_config=game_config,
        analysis_json=analysis_json,
    )


def main():
    if len(sys.argv) > 1:
        first = sys.argv[1]
        if not first.startswith("-") and first not in KNOWN_COMMANDS:
            sys.argv.insert(1, "analyze")
    app()


def resolve_config_path(preset: Optional[str], explicit: Optional[Path]) -> Optional[Path]:
    if explicit:
        return explicit
    if preset:
        candidate = PRESET_DIR / preset
        if candidate.is_file():
            return candidate
        if candidate.with_suffix(".json").is_file():
            return candidate.with_suffix(".json")
        console.print(f"[yellow]Preset {preset} not found in {PRESET_DIR}[/]")
    # Fallback to default if it exists
    default_path = PRESET_DIR / DEFAULT_PRESET
    if default_path.exists():
        return default_path
    return None


def load_game_config(path: Optional[Path]) -> Dict[str, object]:
    if path is None:
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_env_overrides(config: Dict[str, object]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    analysis = config.get("analysis", {}) if isinstance(config, dict) else {}
    if isinstance(analysis, dict):
        addresses = analysis.get("functionAddresses")
        if isinstance(addresses, list) and addresses:
            env["LAZARUS_FUNCTION_ADDRS"] = ",".join(str(item) for item in addresses)
        keywords = analysis.get("keywords")
        if isinstance(keywords, list) and keywords:
            env["LAZARUS_STRING_KEYWORDS"] = ",".join(str(item) for item in keywords)
    return env


def collect_scripts(config: Dict[str, object]) -> Optional[List[str]]:
    analysis = config.get("analysis", {}) if isinstance(config, dict) else {}
    if isinstance(analysis, dict):
        scripts = analysis.get("scripts")
        if isinstance(scripts, list) and scripts:
            return [str(script) for script in scripts]
    return None


def run_pipeline(
    *,
    binary: Path,
    ghidra: Optional[Path],
    output: Path,
    generate_backend: bool,
    generate_mod: bool,
    game_config: Optional[Path],
    log_callback: Optional[Callable[[str], None]] = None,
    analysis_json: Optional[Path] = None,
) -> Dict[str, object]:
    config_data = load_game_config(game_config) if game_config else {}
    env_overrides = build_env_overrides(config_data)
    scripts = collect_scripts(config_data)

    raw_dir = output / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if analysis_json:
        raw_json = raw_dir / "analysis.json"
        shutil.copyfile(analysis_json, raw_json)
    else:
        runner = GhidraRunner(ghidra_install=ghidra)
        raw_json = runner.run_analysis(
            binary,
            output,
            log_callback=log_callback,
            env_overrides=env_overrides,
            scripts=scripts,
        )

    report = load_raw_analysis(raw_json)
    clean = build_clean_report(report)
    clean_path = output / "analysis_report.json"
    payload_schema_path = output / "payload_schema.json"
    write_clean_report(clean, clean_path)
    write_payload_schema(clean, payload_schema_path)

    backend_dir = None
    mod_dir = None

    if generate_backend:
        backend_dir = output / "generated-backend"
        generator = BackendGenerator(clean)
        generator.generate(backend_dir)

    if generate_mod:
        mod_dir = output / "generated-mod"
        mod_generator = ModGenerator(clean)
        mod_generator.generate(mod_dir)

    bundle_dir = write_bundle_artifacts(
        output=output,
        clean_data=clean,
        clean_path=clean_path,
        payload_schema_path=payload_schema_path,
        backend_dir=backend_dir,
        mod_dir=mod_dir,
    )

    return {
        "raw_json": raw_json,
        "clean_report": clean_path,
        "backend_dir": backend_dir,
        "mod_dir": mod_dir,
        "clean_data": clean,
        "payload_schema": payload_schema_path,
        "bundle_dir": bundle_dir,
    }


def write_bundle_artifacts(
    *,
    output: Path,
    clean_data: Dict[str, object],
    clean_path: Path,
    payload_schema_path: Path,
    backend_dir: Optional[Path],
    mod_dir: Optional[Path],
) -> Path:
    bundle_dir = output / "bundle"
    bundle_dir.mkdir(exist_ok=True)
    backend_archive = _archive_dir(backend_dir, bundle_dir, "generated-backend")
    mod_archive = _archive_dir(mod_dir, bundle_dir, "generated-mod")
    manifest = {
        "meta": clean_data.get("meta", {}),
        "artifacts": {
            "analysisReport": str(clean_path),
            "payloadSchema": str(payload_schema_path),
            "backendDir": str(backend_dir) if backend_dir else "",
            "modDir": str(mod_dir) if mod_dir else "",
            "injectorDir": str(mod_dir / "injector") if mod_dir and (mod_dir / "injector").exists() else "",
            "backendArchive": str(backend_archive) if backend_archive else "",
            "modArchive": str(mod_archive) if mod_archive else "",
        },
        "payloadSchemaVersions": clean_data.get("payloadSchemaVersions", {}),
        "routes": clean_data.get("functionPayloadLinks", []),
        "payloadFields": clean_data.get("inferredPayloadFields", []),
        "requestResponseHints": clean_data.get("requestResponseHints", []),
    }
    manifest_path = bundle_dir / "bundle_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    readme_lines = [
        f"# Lazarus Bundle – {clean_data.get('meta', {}).get('program', 'unknown')}",
        "",
        "## Artifacts",
        "",
        f"- Analysis report: `{clean_path}`",
        f"- Payload schema: `{payload_schema_path}`",
    ]
    if backend_dir:
        readme_lines.append(f"- Generated backend: `{backend_dir}`")
        if backend_archive:
            readme_lines.append(f"- Backend archive: `{backend_archive}`")
    if mod_dir:
        readme_lines.append(f"- Generated mod: `{mod_dir}`")
        injector_dir = mod_dir / "injector"
        if injector_dir.exists():
            readme_lines.append(f"- Injector sample: `{injector_dir}`")
            readme_lines.append("- CLI injector: `lazarus inject --pid <pid> --dll <path-to-dll>` (Windows)")
        if mod_archive:
            readme_lines.append(f"- Mod archive: `{mod_archive}`")
    readme_lines.append(f"- Manifest: `{manifest_path}`")
    readme_lines.append("")
    versions = clean_data.get("payloadSchemaVersions")
    if versions:
        readme_lines.append("## Schema versions")
        for key, value in versions.items():
            readme_lines.append(f"- {key}: v{value}")
        readme_lines.append("")

    payload_fields = clean_data.get("inferredPayloadFields", [])
    readme_lines.append("## Payload Fields")
    if payload_fields:
        for field in payload_fields:
            readme_lines.append(
                f"- `{field.get('name')}` ({field.get('typeHint', 'string')}) score={field.get('score', 0)}"
            )
    else:
        readme_lines.append("- None detected.")
    readme_lines.append("")

    links = clean_data.get("functionPayloadLinks", [])
    readme_lines.append("## Endpoint Candidates")
    if links:
        for link in links:
            readme_lines.append(
                f"- {link.get('function')} {link.get('httpVerbs', [])} fields={link.get('payloadFields', [])}"
            )
    else:
        readme_lines.append("- No links detected.")
    readme_lines.append("")

    hooks = clean_data.get("requestResponseHints", [])
    readme_lines.append("## Request/Response Hints")
    if hooks:
        for hint in hooks[:10]:
            readme_lines.append(
                f"- {hint.get('function')} verbs={hint.get('httpVerbs', [])} endpoints={hint.get('endpointStrings', [])}"
            )
    else:
        readme_lines.append("- None.")
    readme_lines.append("")

    readme_lines.append("## Usage")
    readme_lines.append("")
    readme_lines.append("Review `bundle_manifest.json` for machine-readable metadata.")
    readme_lines.append("Deploy the backend/mod/injector artifacts per your platform requirements.")
    (bundle_dir / "README.md").write_text("\n".join(readme_lines), encoding="utf-8")
    _write_deploy_scripts(bundle_dir, backend_archive, mod_archive)
    _write_replay_assets(bundle_dir, clean_data)
    _write_mock_client(bundle_dir)
    _write_per_title_readme(bundle_dir, clean_data, backend_dir, mod_dir)
    return bundle_dir


def _extract_schema_fields(payload: Dict[str, object]) -> List[Dict[str, object]]:
    if isinstance(payload.get("fields"), list):
        return payload["fields"]  # legacy format
    sections = []
    request = payload.get("request", {})
    response = payload.get("response", {})
    if isinstance(request, dict):
        sections.append(request.get("fields", []))
    if isinstance(response, dict):
        sections.append(response.get("fields", []))
    merged: Dict[str, Dict[str, object]] = {}
    for section in sections:
        if not isinstance(section, list):
            continue
        for field in section:
            if not isinstance(field, dict):
                continue
            name = field.get("name")
            if not name:
                continue
            existing = merged.setdefault(name, dict(field))
            dirs = set(existing.get("directions", []))
            dirs.update(field.get("directions", []))
            if dirs:
                existing["directions"] = sorted(dirs)
    return list(merged.values())


def _archive_dir(source: Optional[Path], bundle_dir: Path, name: str) -> Optional[Path]:
    if not source or not source.exists():
        return None
    archive_base = bundle_dir / name
    shutil.make_archive(str(archive_base), "zip", root_dir=source)
    return archive_base.with_suffix(".zip")


def _write_deploy_scripts(
    bundle_dir: Path, backend_archive: Optional[Path], mod_archive: Optional[Path]
) -> None:
    if backend_archive:
        (bundle_dir / "deploy_backend.ps1").write_text(
            f"""Param(
    [string]$ArchivePath = "{backend_archive.name}",
    [string]$TargetDir = "generated-backend"
)

Expand-Archive -Path $ArchivePath -DestinationPath $TargetDir -Force
Push-Location $TargetDir
npm install
npm run build
Write-Host "[lazarus] Backend ready in $TargetDir"
Pop-Location
""",
            encoding="utf-8",
        )
        deploy_sh = bundle_dir / "deploy_backend.sh"
        deploy_sh.write_text(
            f"""#!/usr/bin/env bash
set -euo pipefail
ARCHIVE=${{1:-{backend_archive.name}}}
TARGET=${{2:-generated-backend}}
unzip -oq "$ARCHIVE" -d "$TARGET"
cd "$TARGET"
npm install
npm run build
echo "[lazarus] Backend ready in $TARGET"
""",
            encoding="utf-8",
        )
        try:
            deploy_sh.chmod(0o755)
        except Exception:
            pass

    if mod_archive:
        (bundle_dir / "build_mod.ps1").write_text(
            f"""Param(
    [string]$ArchivePath = "{mod_archive.name}",
    [string]$TargetDir = "generated-mod"
)

Expand-Archive -Path $ArchivePath -DestinationPath $TargetDir -Force
Push-Location $TargetDir
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
Write-Host "[lazarus] Mod built under $TargetDir\\build"
Pop-Location
""",
            encoding="utf-8",
        )
        mod_sh = bundle_dir / "build_mod.sh"
        mod_sh.write_text(
            f"""#!/usr/bin/env bash
set -euo pipefail
ARCHIVE=${{1:-{mod_archive.name}}}
TARGET=${{2:-generated-mod}}
unzip -oq "$ARCHIVE" -d "$TARGET"
cd "$TARGET"
cmake -S . -B build
cmake --build build --config Release
echo "[lazarus] Mod built under $TARGET/build"
""",
            encoding="utf-8",
        )
        try:
            mod_sh.chmod(0o755)
        except Exception:
            pass


def _write_replay_assets(bundle_dir: Path, clean_data: Dict[str, object]) -> None:
    replay_dir = bundle_dir / "replay"
    replay_dir.mkdir(exist_ok=True)
    readme = """# Replay harness assets

Use `python -m lazarus.cli.main replay replay/sample_requests.json --base-url http://localhost:9000`
to send canned requests against the generated backend. Replace the sample payloads with real captures
from packet logs or runtime instrumentation.

File format:

```json
{
  "meta": { "source": "manual" },
  "requests": [
    {
      "description": "Create record",
      "method": "POST",
      "path": "/records",
      "headers": { "Content-Type": "application/json" },
      "body": { "...": "..." }
    }
  ]
}
```
"""
    (replay_dir / "README.md").write_text(readme, encoding="utf-8")
    sample_requests = {
        "meta": {"generatedBy": "lazarus", "hint": "replace with captured traffic"},
        "requests": _build_sample_requests(clean_data),
    }
    (replay_dir / "sample_requests.json").write_text(
        json.dumps(sample_requests, indent=2, sort_keys=True), encoding="utf-8"
    )


def _build_sample_requests(clean_data: Dict[str, object]) -> List[Dict[str, object]]:
    samples: List[Dict[str, object]] = []
    links = clean_data.get("functionPayloadLinks", []) or []
    default_body = {
        "version": 1,
        "recordType": "sample",
        "recordId": "00000000-0000-0000-0000-000000000000",
        "metadata": {"gameId": clean_data.get("meta", {}).get("program", "unknown"), "createdAt": 0},
        "flags": [],
        "fields": [],
        "actions": [],
        "payload": {},
    }
    for link in links[:3]:
        verbs = link.get("httpVerbs", []) or ["POST"]
        endpoints = link.get("endpoints", []) or ["/records"]
        method = verbs[0].upper()
        path = endpoints[0]
        if not path.startswith("/"):
            path = "/" + path
        samples.append(
            {
                "description": f"{link.get('function')} replay",
                "method": method,
                "path": path,
                "headers": {"Content-Type": "application/json"},
                "body": default_body,
            }
        )
    if not samples:
        samples.append(
            {
                "description": "Sample POST /records",
                "method": "POST",
                "path": "/records",
                "headers": {"Content-Type": "application/json"},
                "body": default_body,
            }
        )
    return samples


def _write_mock_client(bundle_dir: Path) -> None:
    client_dir = bundle_dir / "mock-client"
    client_dir.mkdir(exist_ok=True)
    script = """import argparse
import json
import urllib.request
import urllib.error
from urllib.parse import urljoin


def main():
    parser = argparse.ArgumentParser(description="Mock client for Lazarus-generated backend.")
    parser.add_argument("--base-url", default="http://localhost:9000", help="Backend base URL")
    parser.add_argument(
        "--recordings",
        default="../replay/sample_requests.json",
        help="Path to request recording JSON",
    )
    parser.add_argument("--auth-token", help="Bearer token (optional)")
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout (seconds)")
    args = parser.parse_args()

    with open(args.recordings, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    requests_list = payload.get("requests", [])
    for idx, entry in enumerate(requests_list):
        method = (entry.get("method") or "GET").upper()
        path = entry.get("path") or "/"
        if not path.startswith("http://") and not path.startswith("https://"):
            normalized = path if path.startswith("/") else "/" + path
            url = urljoin(args.base_url.rstrip("/") + "/", normalized.lstrip("/"))
        else:
            url = path
        headers = dict(entry.get("headers") or {})
        if args.auth_token and "authorization" not in {k.lower() for k in headers}:
            headers["Authorization"] = f"Bearer {args.auth_token}"
        body = entry.get("body")
        data_bytes = None
        if body is not None:
            if isinstance(body, (dict, list)):
                data_bytes = json.dumps(body).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                data_bytes = body.encode("utf-8")
            elif isinstance(body, bytes):
                data_bytes = body
        req = urllib.request.Request(url, data=data_bytes, method=method)
        for key, value in headers.items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=args.timeout) as resp:
                print(f"[{idx}] {method} {path} -> {resp.status}")
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="ignore")
            print(f"[{idx}] {method} {path} -> HTTP {exc.code}: {err_body}")
        except Exception as exc:
            print(f"[{idx}] {method} {path} -> ERROR {exc}")


if __name__ == "__main__":
    main()
"""
    (client_dir / "mock_client.py").write_text(script, encoding="utf-8")
    readme = """# Mock Client

Send the replay payloads to the generated backend without the full CLI.

```
cd mock-client
python mock_client.py --base-url http://localhost:9000 --recordings ../replay/sample_requests.json
```

Options:

- `--auth-token` to append a `Bearer` token header.
- `--timeout` (seconds) to tweak HTTP timeout per request.
"""
    (client_dir / "README.md").write_text(readme, encoding="utf-8")


def _write_per_title_readme(
    bundle_dir: Path,
    clean_data: Dict[str, object],
    backend_dir: Optional[Path],
    mod_dir: Optional[Path],
) -> None:
    title = clean_data.get("meta", {}).get("program", "unknown")
    readme_path = bundle_dir / "README_per_title.md"
    links = clean_data.get("functionPayloadLinks", [])
    payload_fields = clean_data.get("inferredPayloadFields", [])
    schema_versions = clean_data.get("payloadSchemaVersions", {})
    sections = [
        f"# Lazarus Report — {title}",
        "",
        "## Summary",
        f"- Backend: `{backend_dir}`" if backend_dir else "- Backend: not generated",
        f"- Mod: `{mod_dir}`" if mod_dir else "- Mod: not generated",
        f"- Payload schema versions: {json.dumps(schema_versions) or 'n/a'}",
        "",
        "## Inferred Routes",
    ]
    if links:
        for link in links:
            sections.append(
                f"- `{', '.join(link.get('httpVerbs', [])) or 'GET'}` {', '.join(link.get('endpoints', []) or ['/'])} "
                f"(function `{link.get('function')}`, confidence {link.get('confidence', 0)})"
            )
    else:
        sections.append("- None detected.")
    sections.append("")
    sections.append("## Payload Fields")
    if payload_fields:
        for field in payload_fields[:32]:
            sections.append(
                f"- `{field.get('name')}` type={field.get('typeHint', 'string')} score={field.get('score', 0)} "
                f"sources={', '.join(field.get('sources', [])[:3])}"
            )
    else:
        sections.append("- None detected.")
    sections.append("")
    sections.append("## Next Steps")
    sections.append("- Review payload schema and tighten types.")
    if backend_dir:
        sections.append("- Run `deploy_backend.(ps1|sh)` to bootstrap the backend.")
    if mod_dir:
        sections.append("- Run `build_mod.(ps1|sh)` and integrate hooks/payload bridge.")
    sections.append("- Capture real traffic and extend `replay/sample_requests.json`.")
    readme_path.write_text("\n".join(sections), encoding="utf-8")


def _list_presets() -> None:
    if not PRESET_DIR.exists():
        console.print(f"[red]Config directory not found at {PRESET_DIR}[/]")
        raise typer.Exit(code=1)

    table = Table(title="Available Presets", show_header=True, header_style="bold magenta")
    table.add_column("Preset")
    table.add_column("Scripts")
    count = 0
    for cfg in sorted(PRESET_DIR.glob("*.json")):
        try:
            data = json.loads(cfg.read_text())
            scripts = ", ".join(data.get("analysis", {}).get("scripts", [])) or "default"
        except Exception:
            scripts = "?"
        table.add_row(cfg.name, scripts)
        count += 1

    if count == 0:
        console.print("[yellow]No presets found in config directory[/]")
    else:
        console.print(table)


def _read_key_bytes(path: Path) -> bytes:
    raw = path.read_bytes().strip()
    if not raw:
        raise typer.BadParameter(f"{path} is empty")
    try:
        return bytes.fromhex(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        return base64.b64decode(raw)
    except binascii.Error:
        pass
    return raw


def _require_ed25519() -> None:
    if ed25519 is None:
        console.print("[red]The 'ed25519' dependency is required for this command.[/]")
        console.print("Install it via `pip install ed25519` and try again.")
        raise typer.Exit(code=1)

class RateLimitedConsoleLogger:
    def __init__(self, console, min_interval: float = 0.1) -> None:
        self.console = console
        self.min_interval = min_interval
        self._last = 0.0

    def __call__(self, line: str) -> None:
        now = time.time()
        if now - self._last >= self.min_interval:
            self.console.log(f"[ghidra] {line}")
            self._last = now


if __name__ == "__main__":
    main()

