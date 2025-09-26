import json, time
from pathlib import Path
import yaml
from .config import AppConfig, DEFAULT_CFG

from ..collectors.processes import snapshot_processes, find_suspicious_processes
from ..collectors.network import snapshot_netconns, find_suspicious_netconns
from ..collectors.filesystem import sweep_recent_files
from ..collectors.email_imap import fetch_recent_unread
from ..collectors.email_local import load_eml_dir
from ..collectors.persistence import collect_persistence

from ..analyzers.rules import incident_from_signals
from ..analyzers.email_rules import analyze_emails
from ..analyzers.chain_rules import find_suspicious_proc_chains
from ..analyzers.persistence_rules import analyze_persistence
from ..analyzers.yara_scan import scan_files_with_yara

from ..notifiers.formatting import summarize_incident
from ..notifiers.sms_twilio import build_from_env_and_config

from .policy import load_policy, apply_policy


def _load_cfg_dict() -> dict:
    try:
        return yaml.safe_load(DEFAULT_CFG.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def run_process_scan_and_write_incident(cfg: AppConfig, *, dry: bool = True) -> Path:
    logs_dir = Path(cfg.paths.get("logs", "logs"))
    logs_dir.mkdir(exist_ok=True)
    incidents_dir = logs_dir / "incidents"
    incidents_dir.mkdir(exist_ok=True)

    ts = int(time.time())

    # ---- Processes (with parent/child chain heuristics) ----
    procs = snapshot_processes()
    proc_hits = find_suspicious_processes(procs)
    chain_arts = find_suspicious_proc_chains(procs)  # extra process artifacts

    # ---- Network ----
    netconns = snapshot_netconns()
    net_hits = find_suspicious_netconns(netconns)

    # ---- Filesystem (last 24h) ----
    file_hits = sweep_recent_files(minutes=24 * 60)

    # ---- Config dict (shared) ----
    cfg_dict = _load_cfg_dict()

    # ---- Email (local .eml + optional IMAP) ----
    emails = []
    try:
        eml_dir = (cfg_dict.get("email", {}) or {}).get("local_eml_dir", "mailbox")
        emails.extend(load_eml_dir(eml_dir))
    except Exception:
        pass
    try:
        emails.extend(fetch_recent_unread(cfg_dict))
    except Exception:
        (logs_dir / "imap_error.txt").write_text("IMAP fetch failed (check config/env).", encoding="utf-8")
    email_arts = analyze_emails(emails)

    # ---- Persistence (Run keys, Tasks, Services) ----
    try:
        persist_items = collect_persistence()
    except Exception:
        persist_items = []
    persist_arts = analyze_persistence(persist_items)

    # ---- Optional YARA over suspicious files ----
    yara_arts = []  # << initialize so it's always defined
    try:
        yr_cfg = (cfg_dict.get("yara", {}) or {})
        if yr_cfg.get("enabled", False):
            rules_dir = Path(yr_cfg.get("rules_dir", "rules"))
            max_bytes = int(yr_cfg.get("max_size_bytes", 10 * 1024 * 1024))
            yara_arts = scan_files_with_yara(file_hits, rules_dir=rules_dir, max_size_bytes=max_bytes)
    except Exception:
        # don't let YARA issues break the scan
        pass

    # ---- Build initial incident from core signals ----
    inc = incident_from_signals(proc_hits, net_hits, file_hits, ts)
    inc_dict = inc.__dict__

    # ---- Append additional artifacts (chain/email/persistence/yara) ----
    inc_dict["artifacts"].extend(chain_arts)
    inc_dict["artifacts"].extend(email_arts)
    inc_dict["artifacts"].extend(persist_arts)
    inc_dict["artifacts"].extend(yara_arts)

    # ---- Policy apply (allow/deny + severity recompute) ----
    policy = load_policy(cfg.alerts, cfg_dict)
    inc_dict = apply_policy(inc_dict, policy)

    # ---- Write incident JSON ----
    out = incidents_dir / f"incident_{ts}.json"
    out.write_text(json.dumps(inc_dict, indent=2), encoding="utf-8")

    # ---- Notify if P1 and enabled ----
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