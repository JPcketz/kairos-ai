from pathlib import Path
import json
import time

def _load_incident(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def _section(title: str) -> str:
    return f"## {title}\n\n"

def _list(items):
    return "".join(f"- {i}\n" for i in items) + ("\n" if items else "")

def _artifact_lines(arts, t):
    return [a.get("value","") for a in arts if str(a.get("type","")).lower().startswith(t)]

def render_playbook_md(latest_incident_path: Path, out_dir: Path) -> Path:
    out_dir.mkdir(exist_ok=True)
    inc = _load_incident(latest_incident_path)
    sev = inc.get("sev","P?")
    inc_id = inc.get("id","INC-?")
    summary = inc.get("summary","")
    arts = inc.get("artifacts",[])

    procs = _artifact_lines(arts, "process")
    nets  = _artifact_lines(arts, "network")
    files = _artifact_lines(arts, "file")
    emails= [a for a in arts if str(a.get("type","")).lower().startswith("email")]

    # Build the markdown
    md = []
    md.append(f"# Kairos A.I. Containment Playbook — {inc_id}\n\n")
    md.append(f"**Severity:** {sev}  \n**Summary:** {summary}\n\n")
    md.append(f"_Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}_\n\n")

    md.append(_section("Scope & Signals"))
    if not arts:
        md.append("No artifacts.\n\n")
    else:
        if procs: md.append("**Processes**\n\n" + _list(procs))
        if nets:  md.append("**Network**\n\n"   + _list(nets))
        if files: md.append("**Files**\n\n"     + _list(files))
        if emails:
            md.append("**Email Indicators**\n\n")
            for a in emails[:20]:
                md.append(f"- {a.get('type')}: {a.get('value')}\n")
            md.append("\n")

    md.append(_section("Immediate Actions (Triage)"))
    triage = [
        "Notify on-call (per runbook) and set incident bridge if required.",
        "Capture volatile data **before** terminating processes if feasible (cmdline, netconns, file paths).",
        "Validate user/business context for flagged processes or emails.",
    ]
    md.append(_list(triage))

    if procs:
        md.append(_section("Process Containment"))
        md.append(_list([
            "Identify parent/child process chain and confirm malicious origin.",
            "If malicious: terminate processes and disable persistence (Startup/Run keys, tasks).",
            "Record PIDs and full command lines for the case notes."
        ]))
    if files:
        md.append(_section("File Containment"))
        md.append(_list([
            "Quarantine suspicious files (zip+password or offline share).",
            "Compute and record hashes (SHA256) for each quarantined file.",
            "Search for the same hash/path across other endpoints (scope)."
        ]))
    if nets:
        md.append(_section("Network Containment"))
        md.append(_list([
            "Block egress to suspicious domains/IPs at the perimeter and host firewall.",
            "Capture any additional indicators from DNS/HTTP logs for enrichment.",
        ]))
    if emails:
        md.append(_section("Mail Hygiene"))
        md.append(_list([
            "Quarantine the original emails in the mail system.",
            "Search and purge similar messages (same subject/sender/URL/attachment hash).",
            "Add domains/URLs to the mail filtering block/allow lists as appropriate.",
        ]))

    md.append(_section("Eradication & Recovery"))
    md.append(_list([
        "Remove persistence artifacts and verify clean startup state.",
        "Re-image or restore from known-good backups if system integrity is uncertain.",
        "Monitor closely for reoccurrence (24–72 hours) with tuned detections."
    ]))

    md.append(_section("Documentation"))
    md.append(_list([
        "Update the ticket with actions taken, timelines, indicators, and outcomes.",
        "Attach artifacts: logs, hashes, screenshots, report PDF.",
        "Generate and store the Kairos HTML/PDF report with this playbook."
    ]))

    out_md = out_dir / f"{inc_id}_playbook.md"
    out_md.write_text("".join(md), encoding="utf-8")
    return out_md

def render_ticket_text(latest_incident_path: Path, out_dir: Path) -> Path:
    out_dir.mkdir(exist_ok=True)
    inc = _load_incident(latest_incident_path)
    sev = inc.get("sev","P?")
    inc_id = inc.get("id","INC-?")
    summary = inc.get("summary","")
    arts = inc.get("artifacts",[])

    # Short, helpdesk-friendly text block
    lines = [
        f"[{sev}] {inc_id} — {summary}",
    ]
    for a in arts[:6]:
        lines.append(f"- {a.get('type')}: {a.get('value')}")
    if len(arts) > 6:
        lines.append(f"... (+{len(arts)-6} more artifacts)")
    lines.append("Actions requested: triage, contain (terminate/quarantine), and update ticket with outcomes.")
    text = "\n".join(lines) + "\n"

    out_txt = out_dir / f"{inc_id}_ticket.txt"
    out_txt.write_text(text, encoding="utf-8")
    return out_txt