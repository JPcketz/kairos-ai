from __future__ import annotations
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

app = FastAPI(title="Kairos A.I. — SOC Sidekick")  # <-- define app first

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

# optional: redirect /favicon.ico after app exists
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