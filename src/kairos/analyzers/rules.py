from dataclasses import dataclass
from typing import List, Dict, Any
from ..collectors.processes import ProcInfo
from ..collectors.network import NetConnInfo
from ..collectors.filesystem import FileHit

@dataclass
class Incident:
    id: str
    sev: str
    summary: str
    artifacts: List[Dict[str, Any]]
    recommendations: List[str]

def _sev_from_signals(proc_hits: int, net_hits: int, file_hits: int) -> str:
    types_hit = sum(1 for x in (proc_hits, net_hits, file_hits) if x)
    if types_hit >= 2:
        return "P1"  # multiple independent suspicious signals
    if types_hit == 1:
        return "P2"
    return "P5"

def incident_from_signals(proc_hits: List[ProcInfo], net_hits: List[NetConnInfo], file_hits: List[FileHit], ts: int) -> Incident:
    artifacts: List[Dict[str, Any]] = []
    for h in proc_hits:
        artifacts.append({"type":"process", "value": f"{h.pid} {h.name} :: {h.cmdline}"})
    for n in net_hits:
        artifacts.append({"type":"network", "value": f"pid={n.pid} {n.proc_name} {n.laddr}:{n.lport} -> {n.raddr}:{n.rport} [{n.status}] {n.cmdline}"})
    for f in file_hits:
        artifacts.append({"type":"file", "value": f"{f.path} ({f.ext}, {f.size} bytes, sha256={f.sha256 or 'n/a'})"})

    sev = _sev_from_signals(len(proc_hits), len(net_hits), len(file_hits))

    if sev == "P1":
        summary = "Correlated suspicious activity across multiple signal types"
    elif sev == "P2":
        if proc_hits:
            summary = f"{len(proc_hits)} suspicious process(es) matched heuristic patterns"
        elif net_hits:
            summary = f"{len(net_hits)} suspicious outbound connection(s) by risky process(es)"
        else:
            summary = f"{len(file_hits)} recent suspicious file(s) in monitored paths"
    else:
        summary = "No suspicious signals detected by heuristics"

    recs = (
        [
            "Validate legitimacy with user/context.",
            "If malicious: terminate processes and quarantine files.",
            "Block associated domains/IPs at egress and host firewall.",
            "Preserve evidence (hashes, paths, netconns, cmdlines) prior to remediation."
        ]
        if sev != "P5"
        else ["No action required. Continue monitoring."]
    )

    return Incident(
        id=f"INC-COMPOSITE-{ts}",
        sev=sev,
        summary=summary,
        artifacts=artifacts,
        recommendations=recs,
    )