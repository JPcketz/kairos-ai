from dataclasses import dataclass
from typing import List, Iterable, Tuple
from pathlib import Path
import os, time, hashlib

@dataclass
class FileHit:
    path: str
    ext: str
    size: int
    mtime: float
    sha256: str | None

# extensions that often show up in initial access / lolbins / droppers
SUSPICIOUS_EXTS = {
    ".ps1", ".psm1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd",
    ".lnk", ".dll", ".exe", ".scr"
}

def _sha256_if_small(p: Path, max_bytes: int = 10 * 1024 * 1024) -> str | None:
    try:
        sz = p.stat().st_size
        if sz > max_bytes:
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def _default_roots() -> List[Path]:
    roots: List[Path] = []
    user = os.environ.get("USERPROFILE")
    if user:
        roots.append(Path(user) / "Downloads")
        roots.append(Path(user) / "AppData" / "Local" / "Temp")
        roots.append(Path(user) / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    # common startup for all users
    roots.append(Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
    return roots

def sweep_recent_files(roots: Iterable[Path] | None = None, minutes: int = 1440) -> List[FileHit]:
    """
    Sweep for recently written suspicious files (default: last 24h).
    Returns a list of FileHit.
    """
    roots = list(roots or _default_roots())
    cutoff = time.time() - (minutes * 60)
    hits: List[FileHit] = []

    for root in roots:
        try:
            if not root.exists():
                continue
            for p in root.rglob("*"):
                try:
                    if not p.is_file():
                        continue
                    ext = p.suffix.lower()
                    if ext not in SUSPICIOUS_EXTS:
                        continue
                    st = p.stat()
                    if st.st_mtime < cutoff:
                        continue
                    digest = _sha256_if_small(p)
                    hits.append(FileHit(
                        path=str(p),
                        ext=ext,
                        size=st.st_size,
                        mtime=st.st_mtime,
                        sha256=digest
                    ))
                except Exception:
                    # skip unreadable / transient files
                    continue
        except Exception:
            # root not accessible
            continue
    return hits