from typing import Dict, Any, List

def summarize_incident(inc: Dict[str, Any]) -> tuple[str, str]:
    sev = inc.get("sev", "P?")
    inc_id = inc.get("id", "INC-?")
    summary = inc.get("summary", "")
    artifacts: List[Dict[str, Any]] = inc.get("artifacts", [])

    subject = f"{sev} {inc_id} — {summary}"

    lines = []
    for a in artifacts[:5]:  # keep SMS short
        t = a.get("type", "?")
        v = a.get("value", "")[:200]
        lines.append(f"- {t}: {v}")
    if len(artifacts) > 5:
        lines.append(f"... (+{len(artifacts)-5} more)")

    body = "\n".join(lines) if lines else "No artifacts."
    return subject, body