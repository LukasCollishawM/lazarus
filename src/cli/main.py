from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ..analysis.parser import load_raw_analysis
from ..analysis.report import build_clean_report, write_clean_report
from ..ghidra_automation.runner import GhidraRunner, GhidraRunnerError

console = Console()
app = typer.Typer(help="Lazarus meta-tool CLI")


@app.command()
def analyze(
    binary: Path = typer.Argument(..., exists=True, readable=True, help="Game binary path"),
    ghidra: Path = typer.Option(
        None, "--ghidra", help="Optional Ghidra install directory (defaults detected automatically)"
    ),
    output: Path = typer.Option(
        Path("./lazarus-output"), "--output", "-o", help="Output directory for reports"
    ),
):
    """
    Run headless Ghidra analysis and emit cleaned JSON.
    """
    console.rule("[bold blue]Lazarus Analysis")
    console.print(f"[cyan]Binary:[/] {binary}")
    console.print(f"[cyan]Output:[/] {output}")

    runner = GhidraRunner(ghidra_install=ghidra)
    try:
        raw_json = runner.run_analysis(binary, output, log_callback=lambda line: None)
    except (FileNotFoundError, GhidraRunnerError) as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]✓[/] Raw analysis written to {raw_json}")

    report = load_raw_analysis(raw_json)
    clean = build_clean_report(report)
    clean_path = output / "analysis_report.json"
    write_clean_report(clean, clean_path)

    console.print(f"[green]✓[/] Clean report written to {clean_path}")

    network_fns = clean.get("networkFunctions", [])
    table = Table(title="Network Candidates", show_lines=True)
    table.add_column("Function")
    table.add_column("Imports")
    table.add_column("Entry")
    for fn in network_fns[:5]:
        table.add_row(fn["name"], ", ".join(fn["imports"]), fn["entryPoint"])
    console.print(table)
    console.print("[bold green]Done.[/]")


def main():
    app()


if __name__ == "__main__":
    main()

