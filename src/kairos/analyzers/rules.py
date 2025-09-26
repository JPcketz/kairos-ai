from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from ..collectors.processes import ProcInfo

@dataclass
class Incident:
    id: str
    sev: str
    summary: str
    artifacts: List[Dict[str, Any]]
    recommendations: List[str]

def incident_from_suspicious_procs(hits: List[ProcInfo], ts: int) -> Incident | None:
    if not hits:
        return None
    artifacts = []
    for h in hits:
        artifacts.append({"type":"process", "value": f"{h.pid} {h.name} :: {h.cmdline}"})
    recs = [
        "Validate legitimacy with user/context.",
        "If malicious: terminate process and quarantine dropped files.",
        "Block associated command-and-control domains/IPs at egress.",
        "Capture triage artifacts (cmdline, hashes, netconns) before kill, if feasible."
    ]
    return Incident(
        id=f"INC-PROC-{ts}",
        sev="P2",  # suspicious process execution
        summary=f"{len(hits)} suspicious process(es) matched heuristic patterns",
        artifacts=artifacts,
        recommendations=recs,
    )

def incident_from_clean_snapshot(ts: int) -> Incident:
    return Incident(
        id=f"INC-BASELINE-{ts}",
        sev="P5",
        summary="No suspicious processes detected by heuristics",
        artifacts=[],
        recommendations=["No action required. Continue monitoring."],
    )