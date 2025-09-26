import json, time
from pathlib import Path
from .config import AppConfig

def write_sample_incident(cfg: AppConfig) -> Path:
    logs_dir = Path(cfg.paths.get("logs","logs"))
    logs_dir.mkdir(exist_ok=True)
    incidents_dir = logs_dir / "incidents"
    incidents_dir.mkdir(exist_ok=True)
    ts = int(time.time())
    sample = {
        "id": f"INC-{ts}",
        "sev": "P1",
        "summary": "Suspicious PowerShell download cradle",
        "artifacts": [
            {"type":"process","value":"powershell.exe -nop -w hidden -enc ..."},
            {"type":"network","value":"hxxp://mal.example/payload.bin"}
        ],
        "recommendations":[
            "Terminate suspicious process",
            "Block egress to mal.example at firewall",
            "Acquire volatile memory if feasible",
            "Hash and quarantine payload"
        ]
    }
    out = incidents_dir / f"incident_{ts}.json"
    out.write_text(json.dumps(sample, indent=2), encoding="utf-8")
    return out