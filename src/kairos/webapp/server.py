from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core.config import load_config
from ..core.scaffold import run_process_scan_and_write_incident
from ..reports.html import render_report
from ..reports.pdf import render_pdf_from_incident
from ..reports.playbook import render_playbook_md
from ..reports.bundle import bundle_latest

app = FastAPI(title="Kairos A.I. — SOC Sidekick")

HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = HERE / "templates"
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"])
)

STATIC_DIR = HERE / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# optional favicon redirect
@app.get("/favicon.ico")
def favicon_redirect():
    return RedirectResponse(url="/static/favicon.svg", status_code=302)

def _latest_incident_path(cfg) -> Path | None:
    inc_dir = Path(cfg.paths.get("logs","logs")) / "incidents"
    latest = None
    for p in sorted(inc_dir.glob("incident_*.json")):
        latest = p
    return latest

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    cfg = load_config()
    latest = _latest_incident_path(cfg)
    reports_dir = Path(cfg.paths.get("reports","reports"))
    report_html = reports_dir / "report.html"
    context = {
        "has_incident": latest is not None,
        "has_report": report_html.exists(),
        "request": request
    }
    tpl = ENV.get_template("home.html")
    return tpl.render(**context)

@app.post("/scan")
def scan():
    cfg = load_config()
    run_process_scan_and_write_incident(cfg, dry=True)  # safe default
    return RedirectResponse(url="/report", status_code=303)

@app.get("/report", response_class=HTMLResponse)
def report_view():
    cfg = load_config()
    out = render_report(cfg)
    return FileResponse(path=out, media_type="text/html")

@app.get("/pdf")
def pdf_view():
    cfg = load_config()
    latest = _latest_incident_path(cfg)
    if not latest:
        return RedirectResponse(url="/", status_code=303)
    out = render_pdf_from_incident(latest, Path(cfg.paths.get("reports","reports")))
    return FileResponse(path=out, media_type="application/pdf")

@app.get("/playbook")
def playbook_view():
    cfg = load_config()
    latest = _latest_incident_path(cfg)
    if not latest:
        return RedirectResponse(url="/", status_code=303)
    reports_dir = Path(cfg.paths.get("reports","reports"))
    md = render_playbook_md(latest, reports_dir)
    return FileResponse(path=md, media_type="text/markdown")

@app.get("/bundle")
def bundle_view():
    cfg = load_config()
    logs_dir = Path(cfg.paths.get("logs","logs"))
    inc_dir = logs_dir / "incidents"
    reports_dir = Path(cfg.paths.get("reports","reports"))
    zip_path = bundle_latest(reports_dir, inc_dir)
    return FileResponse(path=zip_path, media_type="application/zip", filename=zip_path.name)

@app.get("/health", response_class=HTMLResponse)
def health(request: Request):
    cfg = load_config()
    logs = Path(cfg.paths.get("logs","logs"))
    reports = Path(cfg.paths.get("reports","reports"))

    # optional deps
    try:
        import yara  # type: ignore
        yara_ok = True
    except Exception:
        yara_ok = False
    try:
        import reportlab  # noqa: F401
        pdf_ok = True
    except Exception:
        pdf_ok = False

    # config snapshot
    try:
        from ..core.config import DEFAULT_CFG
        import yaml
        cfg_dict = yaml.safe_load(DEFAULT_CFG.read_text(encoding="utf-8")) or {}
    except Exception:
        cfg_dict = {}

    alerts = cfg.alerts or {}
    sms_enabled = alerts.get("sms_enabled", False)
    sms_from = alerts.get("sms_from") or os.environ.get("KAIROS_SMS_FROM")
    sms_to   = alerts.get("sms_to") or os.environ.get("KAIROS_SMS_TO")
    sms_ready = sms_enabled and bool(sms_from) and bool(sms_to)

    email_cfg = (cfg_dict.get("email", {}) or {})
    email_enabled = email_cfg.get("enabled", False)
    email_host = email_cfg.get("imap_host")
    email_user = os.environ.get("KAIROS_IMAP_USER")
    email_pass = os.environ.get("KAIROS_IMAP_PASS")
    local_dir  = email_cfg.get("local_eml_dir", "mailbox")
    email_ready = email_enabled and bool(email_host and email_user and email_pass)

    yara_cfg = (cfg_dict.get("yara", {}) or {})
    yara_enabled = yara_cfg.get("enabled", False)
    rules_dir = Path(yara_cfg.get("rules_dir", "rules"))
    rules_exist = rules_dir.exists() and any(rules_dir.glob("*.yar"))
    yara_ready = yara_enabled and yara_ok and rules_exist

    tpl = ENV.get_template("health.html")
    return tpl.render(
        core={"logs": str(logs), "reports": str(reports), "logs_exists": logs.exists(), "reports_exists": reports.exists(), "pdf_ok": pdf_ok},
        sms={"enabled": sms_enabled, "ready": sms_ready, "frm": sms_from, "to": sms_to},
        email={"enabled": email_enabled, "ready": email_ready, "host": email_host, "local_dir": local_dir},
        yara={"enabled": yara_enabled, "ready": yara_ready, "rules_dir": str(rules_dir)}
    )
