import json, time
from pathlib import Path
from .config import AppConfig
from ..collectors.processes import snapshot_processes, find_suspicious_processes
from ..analyzers.rules import incident_from_suspicious_procs, incident_from_clean_snapshot

def write_sample_incident(cfg: AppConfig) -> Path:
    """(Retained) legacy sample – still used if you ever call it elsewhere."""
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

def run_process_scan_and_write_incident(cfg: AppConfig) -> Path:
    logs_dir = Path(cfg.paths.get("logs","logs"))
    logs_dir.mkdir(exist_ok=True)
    incidents_dir = logs_dir / "incidents"
    incidents_dir.mkdir(exist_ok=True)

    ts = int(time.time())
    procs = snapshot_processes()
    hits = find_suspicious_processes(procs)
    inc = incident_from_suspicious_procs(hits, ts) if hits else incident_from_clean_snapshot(ts)

    out = incidents_dir / f"incident_{ts}.json"
    out.write_text(json.dumps(inc.__dict__, indent=2), encoding="utf-8")
    return out