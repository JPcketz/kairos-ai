from dataclasses import dataclass
from typing import List
from pathlib import Path
import email
from email.header import decode_header, make_header
from email.message import Message

@dataclass
class RawEmail:
    subject: str
    from_addr: str
    body_text: str
    attachments: list[tuple[str, str, bytes]]

def _decode(s: str) -> str:
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s

def _walk_message(msg: Message):
    text = []
    atts = []
    for part in msg.walk():
        ctype = part.get_content_type() or ""
        disp  = (part.get("Content-Disposition") or "").lower()
        if part.is_multipart():
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        if "attachment" in disp:
            fname = _decode(part.get_filename() or "attachment.bin")
            atts.append((fname, ctype, payload))
        else:
            if ctype.startswith("text/plain"):
                try:
                    text.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
                except Exception:
                    pass
    return ("\n".join(text)).strip(), atts

def load_eml_dir(eml_dir: str) -> List[RawEmail]:
    root = Path(eml_dir)
    if not root.exists():
        return []
    out: List[RawEmail] = []
    for p in sorted(root.glob("*.eml"))[-20:]:
        try:
            raw = p.read_bytes()
            msg = email.message_from_bytes(raw)
            subj = _decode(msg.get("Subject", ""))
            from_ = _decode(msg.get("From", ""))
            body, atts = _walk_message(msg)
            out.append(RawEmail(subject=subj, from_addr=from_, body_text=body, attachments=atts))
        except Exception:
            continue
    return out