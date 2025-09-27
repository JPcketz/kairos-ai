from __future__ import annotations
from typing import List, Dict
from pathlib import Path

# Optional import — we won't crash if missing
try:
    import yara  # type: ignore
except Exception:
    yara = None

from ..collectors.filesystem import FileHit

def _load_rules(rules_dir: Path):
    if yara is None:
        return None
    if not rules_dir.exists():
        return None
    rule_files = [str(p) for p in rules_dir.glob("*.yar")] + [str(p) for p in rules_dir.glob("*.yara")]
    if not rule_files:
        return None
    # compile all rules in dir as a single namespace
    sources = {Path(p).name: Path(p).read_text(encoding="utf-8", errors="ignore") for p in rule_files}
    return yara.compile(sources=sources)  # type: ignore

def scan_files_with_yara(file_hits: List[FileHit], *, rules_dir: Path, max_size_bytes: int = 10 * 1024 * 1024) -> List[Dict]:
    """
    Run YARA on FileHit paths, return artifacts like:
    {"type":"yara:match","value":"<path> :: <rule> (<ns>)"}
    """
    arts: List[Dict] = []
    if yara is None:
        return arts
    rules = _load_rules(rules_dir)
    if rules is None:
        return arts

    for f in file_hits:
        p = Path(f.path)
        try:
            if not p.exists():
                continue
            if p.stat().st_size > max_size_bytes:
                continue
            # read bytes and match
            data = p.read_bytes()
            matches = rules.match(data=data)
            for m in matches:
                ns = getattr(m, "namespace", "default")
                rule = getattr(m, "rule", str(m))
                arts.append({"type": "yara:match", "value": f"{f.path} :: {rule} ({ns})"})
        except Exception:
            continue
    return arts