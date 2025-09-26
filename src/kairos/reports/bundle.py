from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import json

def bundle_latest(reports_dir: Path, incidents_dir: Path) -> Path:
    reports_dir.mkdir(exist_ok=True)

    # find latest incident json
    latest_json = None
    for p in sorted(incidents_dir.glob("incident_*.json")):
        latest_json = p
    if not latest_json:
        raise FileNotFoundError("No incidents found; run a scan first.")

    # try to read incident id for nicer filename
    inc_id = latest_json.stem
    try:
        data = json.loads(latest_json.read_text(encoding="utf-8"))
        inc_id = data.get("id", inc_id)
    except Exception:
        pass

    # expected companion files (may or may not exist)
    html = reports_dir / "report.html"
    pdf  = next(reports_dir.glob(f"{inc_id}.pdf"), None)
    play = next(reports_dir.glob(f"{inc_id}_playbook.md"), None)
    tick = next(reports_dir.glob(f"{inc_id}_ticket.txt"), None)

    # output zip
    out_zip = reports_dir / f"{inc_id}_handoff.zip"

    with ZipFile(out_zip, "w", compression=ZIP_DEFLATED) as z:
        z.write(latest_json, arcname=latest_json.name)  # always include raw JSON
        if html.exists():
            z.write(html, arcname=html.name)
        if pdf and pdf.exists():
            z.write(pdf, arcname=pdf.name)
        if play and play.exists():
            z.write(play, arcname=play.name)
        if tick and tick.exists():
            z.write(tick, arcname=tick.name)
        z.writestr(
            "README.txt",
            "Kairos A.I. Handoff Bundle\n"
            f"Incident: {inc_id}\n\n"
            "Contents:\n"
            "- incident_*.json  (raw machine-readable incident)\n"
            "- report.html      (pretty HTML report)\n"
            "- <INC>.pdf        (client-friendly PDF)\n"
            "- <INC>_playbook.md (step-by-step containment)\n"
            "- <INC>_ticket.txt (paste into ticketing)\n"
        )

    return out_zip