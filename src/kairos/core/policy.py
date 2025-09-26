from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class Policy:
    # thresholds
    p1_min_types: int = 2          # how many signal types (proc/net/file) → P1
    suppress_p5: bool = True       # hide/noise-reduce: keep P5 but we can mark suppressed

    # allow/deny lists (simple substring matching on artifact values)
    allow_process_names: List[str] = field(default_factory=list)
    allow_paths: List[str] = field(default_factory=list)
    allow_ips_or_domains: List[str] = field(default_factory=list)

    deny_cmdline_keywords: List[str] = field(default_factory=list)
    deny_file_exts: List[str] = field(default_factory=list)

def load_policy(cfg_alerts: Dict[str, Any], cfg_root: Dict[str, Any]) -> Policy:
    """
    Reads policy from config structure. cfg_root is the whole loaded YAML (as dict).
    We keep it forgiving: any missing keys fall back to safe defaults.
    """
    pol = (cfg_root or {}).get("policy", {}) or {}

    thresholds = pol.get("thresholds", {}) or {}
    allow = pol.get("allow", {}) or {}
    deny = pol.get("deny", {}) or {}

    return Policy(
        p1_min_types = int(thresholds.get("p1_min_types", 2)),
        suppress_p5 = bool(thresholds.get("suppress_p5", True)),

        allow_process_names = [x.lower() for x in allow.get("process_names", [])],
        allow_paths = [x.lower() for x in allow.get("paths", [])],
        allow_ips_or_domains = [x.lower() for x in allow.get("ips_or_domains", [])],

        deny_cmdline_keywords = [x.lower() for x in deny.get("process_cmdline_keywords", [])],
        deny_file_exts = [x.lower() for x in deny.get("file_exts", [])],
    )

def _artifact_allowed(art: Dict[str, Any], policy: Policy) -> bool:
    t = (art.get("type") or "").lower()
    v = (art.get("value") or "").lower()

    if t == "process":
        # allow if process name explicitly allowed
        for name in policy.allow_process_names:
            if f" {name} " in f" {v} ":
                return True

    if t == "file":
        for p in policy.allow_paths:
            if p and p in v:
                return True

    if t == "network":
        for host in policy.allow_ips_or_domains:
            if host and host in v:
                return True

    return False

def _artifact_denied(art: Dict[str, Any], policy: Policy) -> bool:
    t = (art.get("type") or "").lower()
    v = (art.get("value") or "").lower()

    if t == "process":
        for kw in policy.deny_cmdline_keywords:
            if kw and kw in v:
                return True

    if t == "file":
        # deny by extension (very simple suffix check inside value)
        for ext in policy.deny_file_exts:
            if ext and v.endswith(ext):
                return True

    return False

def _count_types(arts: List[Dict[str, Any]]) -> int:
    kinds = set()
    for a in arts:
        t = (a.get("type") or "").lower()
        if t in {"process","network","file"}:
            kinds.add(t)
    return len(kinds)

def apply_policy(incident: Dict[str, Any], policy: Policy) -> Dict[str, Any]:
    """
    Returns a *new* incident dict with artifacts filtered by allow/deny,
    and severity possibly adjusted per thresholds.
    """
    arts = list(incident.get("artifacts", []))

    # 1) remove explicitly allowed artifacts
    arts = [a for a in arts if not _artifact_allowed(a, policy)]

    # 2) keep denied artifacts (they are strong signals), but we don't *add* new ones here
    # (if you want, you could escalate severity if a denied hit exists)
    denied_hit = any(_artifact_denied(a, policy) for a in arts)

    # 3) recompute severity based on how many signal types remain
    types_hit = _count_types(arts)
    sev = incident.get("sev", "P5")
    if types_hit >= policy.p1_min_types or denied_hit:
        sev = "P1"
    elif types_hit == 1:
        sev = "P2"
    else:
        sev = "P5"

    # 4) possibly suppress P5 noise (we keep the record but clarify summary)
    summary = incident.get("summary", "")
    if sev == "P5" and policy.suppress_p5:
        summary = "No suspicious signals after policy allowlist filtering"

    out = dict(incident)
    out["artifacts"] = arts
    out["sev"] = sev
    out["summary"] = summary
    return out