from typing import List, Dict
import os

from ..collectors.persistence import PersistItem

RISKY_EXTS = {".exe",".scr",".ps1",".js",".jse",".vbs",".vbe",".wsf",".hta",".lnk",".bat",".cmd",".dll",".jar"}
RISKY_PATH_HINTS = [
    r"\appdata\local\temp",
    r"\appdata\local\microsoft\windows\inetcache",
    r"\downloads",
    r"\programdata",
    r"\users\public",
]
SUSP_CMDS = [
    "powershell -enc", "frombase64string", "invoke-webrequest", "bitsadmin",
    "regsvr32 /i:", "rundll32 http", "mshta http", "wscript ", "cscript "
]

def _low(s: str) -> str:
    return (s or "").lower()

def _suspicious_path(path: str) -> bool:
    lp = _low(path)
    if any(h in lp for h in RISKY_PATH_HINTS):
        return True
    _, ext = os.path.splitext(lp)
    if ext in RISKY_EXTS:
        return True
    if any(k in lp for k in SUSP_CMDS):
        return True
    return False

def analyze_persistence(items: List[PersistItem]) -> List[Dict]:
    arts: List[Dict] = []
    for it in items:
        if _suspicious_path(it.path):
            arts.append({
                "type": "persistence",
                "value": f"{it.ptype}:{it.name} => {it.path} ({it.details or ''})".strip()
            })
    return arts