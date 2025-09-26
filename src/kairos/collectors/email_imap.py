from dataclasses import dataclass
from typing import List, Optional
import os
from imapclient import IMAPClient
import email
from email.header import decode_header, make_header
from email.message import Message

@dataclass
class RawEmail:
    subject: str
    from_addr: str
    body_text: str
    attachments: list[tuple[str, str, bytes]]  # (filename, content_type, data)

def _decode(s: Optional[str]) -> str:
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s

def _walk_message(msg: Message) -> tuple[str, list[tuple[str,str,bytes]]]:
    text = []
    atts: list[tuple[str,str,bytes]] = []
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

def fetch_recent_unread(cfg: dict) -> List[RawEmail]:
    if not (cfg.get("email", {}).get("enabled", False)):
        return []
    host = cfg.get("email", {}).get("imap_host", "")
    port = int(cfg.get("email", {}).get("imap_port", 993))
    folder = cfg.get("email", {}).get("folder", "INBOX")
    limit = int(cfg.get("email", {}).get("max_messages", 10))

    user = os.environ.get("KAIROS_IMAP_USER", "")
    pwd  = os.environ.get("KAIROS_IMAP_PASS", "")
    if not host or not user or not pwd:
        # Not configured; silently do nothing
        return []

    out: List[RawEmail] = []
    with IMAPClient(host, port=port, ssl=True) as client:
        client.login(user, pwd)
        client.select_folder(folder, readonly=True)
        # recent unread first
        uids = client.search(["UNSEEN"])
        # newest last; slice last N
        uids = uids[-limit:]
        for uid in uids:
            raw_bytes = client.fetch([uid], ["RFC822"])[uid][b"RFC822"]
            msg = email.message_from_bytes(raw_bytes)
            subj = _decode(msg.get("Subject", ""))
            from_ = _decode(msg.get("From", ""))
            body, atts = _walk_message(msg)
            out.append(RawEmail(subject=subj, from_addr=from_, body_text=body, attachments=atts))
    return out