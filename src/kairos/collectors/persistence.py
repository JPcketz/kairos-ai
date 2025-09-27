from dataclasses import dataclass
from typing import List, Optional
import os, subprocess, shlex
from pathlib import Path

try:
    import winreg  # type: ignore
except Exception:
    winreg = None  # non-Windows fallback; returns no results

@dataclass
class PersistItem:
    ptype: str     # runkey | task | service
    name: str
    path: str
    details: Optional[str] = None

# ---- Registry Run/RunOnce ----

_RUN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
]

def _open_key(root, subkey):
    try:
        return winreg.OpenKey(root, subkey)
    except Exception:
        return None

def _root_from_str(root_str):
    mapping = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
    }
    return mapping.get(root_str)

def collect_runkeys() -> List[PersistItem]:
    items: List[PersistItem] = []
    if winreg is None:
        return items

    for full in _RUN_KEYS:
        try:
            root_str, sub = full.split("\\", 1)
        except ValueError:
            continue
        root = _root_from_str(root_str)
        if not root:
            continue
        # enumerate values
        try:
            with winreg.OpenKey(root, sub) as k:
                i = 0
                while True:
                    try:
                        name, val, _typ = winreg.EnumValue(k, i)
                        i += 1
                        if isinstance(val, bytes):
                            try:
                                val = val.decode("utf-8", "ignore")
                            except Exception:
                                val = ""
                        items.append(PersistItem(
                            ptype="runkey",
                            name=f"{root_str}\\{sub}\\{name}",
                            path=str(val or ""),
                            details=None,
                        ))
                    except OSError:
                        break
        except Exception:
            continue
    return items

# ---- Scheduled Tasks (schtasks) ----

def collect_tasks() -> List[PersistItem]:
    items: List[PersistItem] = []
    try:
        # /fo LIST /v gives action lines; keep it light and robust
        out = subprocess.check_output(
            ["schtasks.exe", "/query", "/fo", "LIST", "/v"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            stderr=subprocess.STDOUT
        ).decode("utf-8", "ignore").splitlines()
    except Exception:
        return items

    current = {}
    def flush_task():
        if current.get("TaskName"):
            action = current.get("Actions", "") or current.get("Task To Run", "")
            items.append(PersistItem(
                ptype="task",
                name=current.get("TaskName","").strip(),
                path=action.strip(),
                details=current.get("Schedule","") or current.get("Run As User","")
            ))

    for line in out:
        if line.strip() == "":
            if current:
                flush_task()
                current = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k in ("TaskName","Actions","Task To Run","Schedule","Run As User"):
                current[k] = v
    if current:
        flush_task()

    return items

# ---- Services (psutil) ----

def collect_services() -> List[PersistItem]:
    items: List[PersistItem] = []
    try:
        import psutil
        for s in psutil.win_service_iter():  # type: ignore[attr-defined]
            try:
                info = s.as_dict()
                name = info.get("name","")
                binpath = info.get("binpath","") or ""
                start_type = info.get("start_type","")
                status = info.get("status","")
                items.append(PersistItem(
                    ptype="service",
                    name=name,
                    path=str(binpath),
                    details=f"{start_type}/{status}"
                ))
            except Exception:
                continue
    except Exception:
        pass
    return items

def collect_persistence() -> List[PersistItem]:
    items: List[PersistItem] = []
    try:
        items.extend(collect_runkeys())
    except Exception:
        pass
    try:
        items.extend(collect_tasks())
    except Exception:
        pass
    try:
        items.extend(collect_services())
    except Exception:
        pass
    return items