from pathlib import Path
from datetime import datetime
import json
from jinja2 import Template
from ..core.config import AppConfig

TEMPLATE = Template("""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Kairos Report</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem; }
h1 { margin-bottom: 0; }
small { color: #555; }
pre { background: #111; color: #eee; padding: 1rem; border-radius: 8px; overflow:auto; }
.badge { display:inline-block; padding: 2px 8px; border-radius: 12px; background:#222; color:#0ff; font-weight:600; }
.card { border:1px solid #333; border-radius:12px; padding:1rem; margin:1rem 0; }
</style>
</head>
<body>
  <h1>Kairos A.I. — Report</h1>
  <small>Generated {{ now }}</small>
  {% if incident %}
  <div class="card">
    <div><span class="badge">{{ incident.sev }}</span> <b>{{ incident.id }}</b></div>
    <p>{{ incident.summary }}</p>
    <h3>Artifacts</h3>
    <ul>
      {% for a in incident.artifacts %}
        <li><b>{{ a.type }}</b>: <code>{{ a.value }}</code></li>
      {% endfor %}
    </ul>
    <h3>Recommendations</h3>
    <ul>
      {% for r in incident.recommendations %}
        <li>{{ r }}</li>
      {% endfor %}
    </ul>
    <h3>Raw</h3>
    <pre>{{ raw }}</pre>
  </div>
  {% else %}
    <p>No incidents found yet. Run <code>python -m src.kairos scan</code> first.</p>
  {% endif %}
</body>
</html>
""")

def render_report(cfg: AppConfig) -> Path:
    reports_dir = Path(cfg.paths.get("reports","reports"))
    reports_dir.mkdir(exist_ok=True)
    incidents_dir = Path(cfg.paths.get("logs","logs")) / "incidents"
    incidents_dir.mkdir(exist_ok=True)

    latest = None
    for p in sorted(incidents_dir.glob("incident_*.json")):
        latest = p
    data = None
    raw = ""
    if latest and latest.exists():
        raw = latest.read_text(encoding="utf-8")
        data = json.loads(raw)

    out = reports_dir / "report.html"
    out.write_text(TEMPLATE.render(now=datetime.now(), incident=data, raw=raw), encoding="utf-8")
    return out