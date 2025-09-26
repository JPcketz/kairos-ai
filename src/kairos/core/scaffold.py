import json, time
from pathlib import Path
from .config import AppConfig
from ..collectors.processes import snapshot_processes, find_suspicious_processes
from ..collectors.network import snapshot_netconns, find_suspicious_netconns
from ..collectors.filesystem import sweep_recent_files
from ..analyzers.rules import incident_from_signals

def run_process_scan_and_write_incident(cfg: AppConfig) -> Path:
    logs_dir = Path(cfg.paths.get("logs","logs"))
    logs_dir.mkdir(exist_ok=True)
    incidents_dir = logs_dir / "incidents"
    incidents_dir.mkdir(exist_ok=True)

    ts = int(time.time())

    # processes
    procs = snapshot_processes()
    proc_hits = find_suspicious_processes(procs)

    # network
    netconns = snapshot_netconns()
    net_hits = find_suspicious_netconns(netconns)

    # filesystem (last 24h)
    file_hits = sweep_recent_files(minutes=24*60)

    inc = incident_from_signals(proc_hits, net_hits, file_hits, ts)

    out = incidents_dir / f"incident_{ts}.json"
    out.write_text(json.dumps(inc.__dict__, indent=2), encoding="utf-8")
    return out