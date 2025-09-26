import argparse
from pathlib import Path
from rich.console import Console
from .core.config import ensure_default_config, load_config
from .core.scaffold import run_process_scan_and_write_incident
from .reports.html import render_report

console = Console()

def main():
    parser = argparse.ArgumentParser(prog="kairos", description="Kairos A.I. — SOC Sidekick")
    parser.add_argument("--init", action="store_true", help="Create default config if missing")
    sub = parser.add_subparsers(dest="cmd")

    # scan subcommand
    scan = sub.add_parser("scan", help="Run a sample scan (placeholder)")
    scan.add_argument("--dry", action="store_true", help="Dry run: no system changes")

    # report subcommand (+ --open flag)
    rep = sub.add_parser("report", help="Render latest report")
    rep.add_argument("--open", action="store_true", help="Open the report after rendering")

    args = parser.parse_args()

    if args.init:
        cfg_path = ensure_default_config()
        console.print(f"[bold green]Config ready:[/bold green] {cfg_path}")

    if args.cmd == "scan":
        cfg = load_config()
        out = run_process_scan_and_write_incident(cfg)
        console.print(f"[bold yellow]Scan complete[/bold yellow] → {out}")

    elif args.cmd == "report":
        cfg = load_config()
        out = render_report(cfg)
        console.print(f"[bold cyan]Report rendered[/bold cyan] → {out}")
        if getattr(args, "open", False):
            import webbrowser
            webbrowser.open(Path(out).resolve().as_uri())

    elif not args.init:
        parser.print_help()