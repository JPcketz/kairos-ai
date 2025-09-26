from dataclasses import dataclass
from typing import List, Dict, Any
from ..collectors.processes import ProcInfo
from ..collectors.network import NetConnInfo

@dataclass
class Incident:
    id: str
    sev: str
    summary: str
    artifacts: List[Dict[str, Any]]
    recommendations: List[str]

def _sev_from_signals(proc_hits: int, net_hits: int) -> str:
    if proc_hits and net_hits:
        return "P1"  # suspicious proc + outbound public net = higher risk
    if proc_hits or net_hits:
        return "P2"
    return "P5"

def incident_from_signals(proc_hits: List[ProcInfo], net_hits: List[NetConnInfo], ts: int) -> Incident:
    artifacts: List[Dict[str, Any]] = []
    for h in proc_hits:
        artifacts.append({"type":"process", "value": f"{h.pid} {h.name} :: {h.cmdline}"})
    for n in net_hits:
        artifacts.append({"type":"network", "value": f"pid={n.pid} {n.proc_name} {n.laddr}:{n.lport} -> {n.raddr}:{n.rport} [{n.status}] {n.cmdline}"})

    sev = _sev_from_signals(len(proc_hits), len(net_hits))
    if sev == "P1":
        summary = f"{len(proc_hits)} suspicious process(es) with outbound public connections"
    elif sev == "P2" and proc_hits:
        summary = f"{len(proc_hits)} suspicious process(es) matched heuristic patterns"
    elif sev == "P2" and net_hits:
        summary = f"{len(net_hits)} suspicious outbound connection(s) by risky process(es)"
    else:
        summary = "No suspicious signals detected by heuristics"

    recs = [
        "Validate legitimacy with user/context.",
        "If malicious: terminate process and quarantine dropped files.",
        "Block associated domains/IPs at egress and host firewall.",
        "Capture triage artifacts (cmdline, hashes, netconns) before kill, if feasible."
    ] if sev != "P5" else ["No action required. Continue monitoring."]

    return Incident(
        id=f"INC-COMPOSITE-{ts}",
        sev=sev,
        summary=summary,
        artifacts=artifacts,
        recommendations=recs,
    )