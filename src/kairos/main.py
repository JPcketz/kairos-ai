import argparse
from pathlib import Path
from rich.console import Console
from .core.config import ensure_default_config, load_config
from .core.scaffold import run_process_scan_and_write_incident
from .reports.html import render_report
from .reports.pdf import render_pdf_from_incident
from .reports.playbook import render_playbook_md, render_ticket_text
from .reports.bundle import bundle_latest

console = Console()

def main():
    parser = argparse.ArgumentParser(prog="kairos", description="Kairos A.I. — SOC Sidekick")
    parser.add_argument("--init", action="store_true", help="Create default config if missing")
    sub = parser.add_subparsers(dest="cmd")

    # scan
    scan = sub.add_parser("scan", help="Run a heuristic scan")
    scan.add_argument("--dry", action="store_true", help="Dry run: no outbound notifications")
    scan.add_argument("--enable-sms", action="store_true", help="Enable SMS for this run (overrides config to true)")

    # report (HTML)
    rep = sub.add_parser("report", help="Render latest HTML report")
    rep.add_argument("--open", action="store_true", help="Open the report after rendering")

    # pdf
    pdf = sub.add_parser("pdf", help="Render the latest incident as a PDF")

    # playbook
    play = sub.add_parser("playbook", help="Generate a containment playbook and ticket text from latest incident")
    play.add_argument("--open", action="store_true", help="Open the playbook after rendering")

    # bundle
    bundle = sub.add_parser("bundle", help="Zip latest artifacts (HTML, PDF, playbook, ticket, JSON) for handoff")

    args = parser.parse_args()

    if args.init:
        cfg_path = ensure_default_config()
        console.print(f"[bold green]Config ready:[/bold green] {cfg_path}")

    if args.cmd == "scan":
        cfg = load_config()
        if getattr(args, "enable_sms", False):
            cfg.alerts["sms_enabled"] = True
        out = run_process_scan_and_write_incident(cfg, dry=getattr(args, "dry", False))
        console.print(f"[bold yellow]Scan complete[/bold yellow] → {out}")

    elif args.cmd == "report":
        cfg = load_config()
        out = render_report(cfg)
        console.print(f"[bold cyan]Report rendered[/bold cyan] → {out}")
        if getattr(args, "open", False):
            import webbrowser
            webbrowser.open(Path(out).resolve().as_uri())

    elif args.cmd == "pdf":
        cfg = load_config()
        logs_dir = Path(cfg.paths.get("logs", "logs"))
        inc_dir = logs_dir / "incidents"
        latest = None
        for p in sorted(inc_dir.glob("incident_*.json")):
            latest = p
        if not latest:
            console.print("[red]No incidents found. Run 'kairos scan' first.[/red]")
            return
        out = render_pdf_from_incident(latest, Path(cfg.paths.get("reports", "reports")))
        console.print(f"[bold magenta]PDF written[/bold magenta] → {out}")

    elif args.cmd == "playbook":
        cfg = load_config()
        logs_dir = Path(cfg.paths.get("logs", "logs"))
        inc_dir = logs_dir / "incidents"
        latest = None
        for p in sorted(inc_dir.glob("incident_*.json")):
            latest = p
        if not latest:
            console.print("[red]No incidents found. Run 'kairos scan' first.[/red]")
            return
        reports_dir = Path(cfg.paths.get("reports", "reports"))
        md_path = render_playbook_md(latest, reports_dir)
        txt_path = render_ticket_text(latest, reports_dir)
        console.print(f"[bold magenta]Playbook written[/bold magenta] → {md_path}")
        console.print(f"[bold magenta]Ticket text written[/bold magenta] → {txt_path}")
        if getattr(args, "open", False):
            import webbrowser
            webbrowser.open(md_path.resolve().as_uri())

    elif args.cmd == "bundle":
        cfg = load_config()
        logs_dir = Path(cfg.paths.get("logs", "logs"))
        inc_dir = logs_dir / "incidents"
        reports_dir = Path(cfg.paths.get("reports", "reports"))
        try:
            zip_path = bundle_latest(reports_dir, inc_dir)
            console.print(f"[bold green]Bundle created[/bold green] → {zip_path}")
        except FileNotFoundError:
            console.print("[red]No incidents found. Run 'kairos scan' first.[/red]")

    elif not args.init:
        parser.print_help()