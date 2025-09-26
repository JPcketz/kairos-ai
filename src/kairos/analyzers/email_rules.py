from dataclasses import dataclass
from typing import List, Dict, Any
import re
from ..collectors.email_imap import RawEmail as ImapEmail
from ..collectors.email_local import RawEmail as LocalEmail

RISKY_EXTS = {".exe",".scr",".ps1",".js",".jse",".vbs",".vbe",".wsf",".hta",".lnk",".bat",".cmd",".dll"}
URL_SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly"}
SUSP_TLDS = {".ru",".cn",".zip",".mov",".top",".click",".link"}

_url_re = re.compile(r"https?://[^\s)>\]]+", re.IGNORECASE)

def _extract_urls(txt: str) -> List[str]:
    if not txt:
        return []
    urls = _url_re.findall(txt)
    # light normalize
    urls = [u.rstrip(".,);]\"'") for u in urls]
    return urls[:25]

def analyze_emails(emails: List[ImapEmail] | List[LocalEmail]) -> List[Dict[str, Any]]:
    artifacts: List[Dict[str, Any]] = []
    for m in emails:
        urls = _extract_urls(m.body_text)
        risky_urls = []
        for u in urls:
            lu = u.lower()
            if any(dom in lu for dom in URL_SHORTENERS) or any(lu.endswith(tld) for tld in SUSP_TLDS):
                risky_urls.append(u)
        for u in risky_urls[:10]:
            artifacts.append({"type":"email:url", "value": f"{m.from_addr} | {m.subject} | {u}"})

        for (fname, ctype, _data) in m.attachments[:10]:
            low = (fname or "").lower()
            for ext in RISKY_EXTS:
                if low.endswith(ext):
                    artifacts.append({"type":"email:attachment", "value": f"{m.from_addr} | {m.subject} | {fname} ({ctype})"})
                    break
    return artifacts