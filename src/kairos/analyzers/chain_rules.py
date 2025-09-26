from typing import List, Dict
from ..collectors.processes import ProcInfo

# Parents that shouldn't spawn scripting/LOLBINs in normal use
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "visio.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe"}
MAILERS = {"outlook.exe", "thunderbird.exe"}
SCRIPTY = {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "cmd.exe"}

SUSP_CMD_KEYWORDS = [
    " -enc", "downloadstring", "invoke-webrequest", "bitsadmin", "frombase64string"
]

def find_suspicious_proc_chains(procs: List[ProcInfo]) -> List[Dict]:
    """Return artifacts (type=process) describing suspicious parent->child relationships."""
    arts: List[Dict] = []
    for p in procs:
        child = p.name
        parent = (p.parent_name or "")
        if not parent:
            continue

        # suspicious child?
        child_is_scripty = child in SCRIPTY or any(k in (p.cmdline or "") for k in SUSP_CMD_KEYWORDS)
        if not child_is_scripty:
            continue

        # suspicious parent category?
        parent_is_office = parent in OFFICE
        parent_is_browser = parent in BROWSERS
        parent_is_mail = parent in MAILERS

        if parent_is_office or parent_is_browser or parent_is_mail:
            arts.append({
                "type": "process",  # normalize so policy counts this under process
                "value": f"{parent} (ppid={p.ppid}) -> {child} (pid={p.pid}) :: {p.cmdline}"
            })
    return arts