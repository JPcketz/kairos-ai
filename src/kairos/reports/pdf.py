from pathlib import Path
import json, time
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib import colors

def _wrap_text(c, text, x, y, max_width, line_height):
    # naive word-wrapping for PDF
    words = text.split()
    line = ""
    lines = []
    for w in words:
        test = (line + " " + w).strip()
        if c.stringWidth(test, "Helvetica", 10) <= max_width:
            line = test
        else:
            lines.append(line)
            line = w
    if line:
        lines.append(line)
    for ln in lines:
        c.drawString(x, y, ln)
        y -= line_height
    return y

def render_pdf_from_incident(latest_incident_path: Path, out_dir: Path) -> Path:
    out_dir.mkdir(exist_ok=True)
    if not latest_incident_path.exists():
        raise FileNotFoundError("No incident JSON found; run a scan first.")

    data = json.loads(latest_incident_path.read_text(encoding="utf-8"))
    sev = data.get("sev","P?")
    inc_id = data.get("id","INC-?")
    summary = data.get("summary","")
    arts = data.get("artifacts",[])
    recs = data.get("recommendations",[])

    out = out_dir / f"{inc_id}.pdf"
    c = canvas.Canvas(str(out), pagesize=LETTER)
    width, height = LETTER
    margin = 0.75 * inch
    x = margin
    y = height - margin

    # Header
    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.black)
    c.drawString(x, y, "Kairos A.I. — Incident Report")
    y -= 18 + 6
    c.setFont("Helvetica", 10)
    c.setFillColor(colors.gray)
    c.drawString(x, y, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 14

    # Badge-ish sev/id
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x, y, f"{sev}  {inc_id}")
    y -= 16

    # Summary
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x, y, "Summary")
    y -= 14
    c.setFont("Helvetica", 10)
    y = _wrap_text(c, summary, x, y, width - 2*margin, 12)
    y -= 8

    # Artifacts
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x, y, "Artifacts")
    y -= 14
    c.setFont("Helvetica", 10)
    if not arts:
        c.drawString(x, y, "None")
        y -= 12
    else:
        for a in arts[:30]:
            t = a.get("type","?")
            v = a.get("value","")
            y = _wrap_text(c, f"- {t}: {v}", x, y, width - 2*margin, 12)
            if y < margin:
                c.showPage(); y = height - margin; x = margin
                c.setFont("Helvetica", 10)

    # Recommendations
    if y < (margin + 60):
        c.showPage(); y = height - margin; x = margin
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x, y, "Recommendations")
    y -= 14
    c.setFont("Helvetica", 10)
    if not recs:
        c.drawString(x, y, "None")
        y -= 12
    else:
        for r in recs[:20]:
            y = _wrap_text(c, f"- {r}", x, y, width - 2*margin, 12)
            if y < margin:
                c.showPage(); y = height - margin; x = margin
                c.setFont("Helvetica", 10)

    c.showPage()
    c.save()
    return out