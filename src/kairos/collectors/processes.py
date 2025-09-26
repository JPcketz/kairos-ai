from dataclasses import dataclass
from typing import List, Optional, Tuple
import psutil

@dataclass
class ProcInfo:
    pid: int
    ppid: Optional[int]
    name: str
    username: Optional[str]
    cmdline: str
    parent_name: Optional[str]
    parent_cmdline: Optional[str]

SUSPECT_PATTERNS = [
    "powershell -enc",
    "powershell -e ",
    "mshta http",
    "wscript ",
    "cscript ",
    "rundll32 http",
    "regsvr32 /s /u /i:",
    "cmd /c powershell",
    "cmd.exe /c powershell",
]

def _safe_cmdline(p: psutil.Process) -> str:
    try:
        return " ".join(p.cmdline()).lower()
    except Exception:
        return ""

def _safe_name(p: psutil.Process) -> str:
    try:
        return (p.name() or "").lower()
    except Exception:
        return "unknown"

def _safe_user(p: psutil.Process) -> Optional[str]:
    try:
        return p.username()
    except Exception:
        return None

def _parent_info(p: psutil.Process) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    try:
        ppid = p.ppid()
        if not ppid:
            return None, None, None
        try:
            pp = psutil.Process(ppid)
            return ppid, _safe_name(pp), _safe_cmdline(pp)
        except Exception:
            return ppid, None, None
    except Exception:
        return None, None, None

def snapshot_processes() -> List[ProcInfo]:
    """Return a lightweight snapshot of running processes (with parent info)."""
    procs: List[ProcInfo] = []
    for p in psutil.process_iter(attrs=[]):
        ppid, pname, pcmd = _parent_info(p)
        procs.append(
            ProcInfo(
                pid=p.pid,
                ppid=ppid,
                name=_safe_name(p),
                username=_safe_user(p),
                cmdline=_safe_cmdline(p),
                parent_name=pname,
                parent_cmdline=pcmd,
            )
        )
    return procs

def find_suspicious_processes(procs: List[ProcInfo]) -> List[ProcInfo]:
    """Filter processes whose cmdlines match simple suspicious patterns."""
    hits: List[ProcInfo] = []
    for proc in procs:
        cl = proc.cmdline
        if not cl:
            continue
        if any(pat in cl for pat in SUSPECT_PATTERNS):
            hits.append(proc)
    return hits