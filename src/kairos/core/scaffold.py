import json, time
from pathlib import Path
import yaml
from .config import AppConfig, DEFAULT_CFG
from ..collectors.processes import snapshot_processes, find_suspicious_processes
from ..collectors.network import snapshot_netconns, find_suspicious_netconns
from ..collectors.filesystem import sweep_recent_files
from ..collectors.email_imap import fetch_recent_unread
from ..collectors.email_local import load_eml_dir
from ..analyzers.email_rules import analyze_emails
from ..analyzers.rules import incident_from_signals
from ..notifiers.formatting import summarize_incident
from ..notifiers.sms_twilio import build_from_env_and_config
from .policy import load_policy, apply_policy

def _load_cfg_dict() -> dict:
    try:
        return yaml.safe_load(DEFAULT_CFG.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}

def run_process_scan_and_write_incident(cfg: AppConfig, *, dry: bool = True) -> Path:
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

    # emails
    cfg_dict = _load_cfg_dict()
    eml_dir = (cfg_dict.get("email", {}) or {}).get("local_eml_dir", "mailbox")
    emails: list = []
    try:
        emails.extend(load_eml_dir(eml_dir))
    except Exception:
        pass
    try:
        emails.extend(fetch_recent_unread(cfg_dict))
    except Exception:
        # failing IMAP should not break scan; log if needed
        (logs_dir / "imap_error.txt").write_text("IMAP fetch failed (check config/env).", encoding="utf-8")

    email_arts = analyze_emails(emails)

    # initial incident from signals (we'll pass file hits for counting; email artifacts get appended)
    inc = incident_from_signals(proc_hits, net_hits, file_hits, ts)
    inc_dict = inc.__dict__
    inc_dict["artifacts"].extend(email_arts)

    # policy
    policy = load_policy(cfg.alerts, cfg_dict)
    inc_dict = apply_policy(inc_dict, policy)

    # write
    out = incidents_dir / f"incident_{ts}.json"
    out.write_text(json.dumps(inc_dict, indent=2), encoding="utf-8")

    # notify on P1 (after policy)
    try:
        alerts = cfg.alerts or {}
        if alerts.get("sms_enabled", False) and inc_dict.get("sev") == "P1":
            subject, body = summarize_incident(inc_dict)
            if dry:
                (logs_dir / "dryrun.txt").write_text(f"Would SMS:\n{subject}\n{body}\n", encoding="utf-8")
            else:
                twilio = build_from_env_and_config(alerts)
                twilio.notify(subject, body)
    except Exception as e:
        (logs_dir / "notify_error.txt").write_text(str(e), encoding="utf-8")

    return out