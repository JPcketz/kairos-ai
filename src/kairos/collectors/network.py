from dataclasses import dataclass
from typing import List, Optional, Tuple
import psutil
import ipaddress

@dataclass
class NetConnInfo:
    pid: int
    laddr: str
    raddr: Optional[str]
    lport: Optional[int]
    rport: Optional[int]
    status: str
    proc_name: str
    cmdline: str

SUSPICIOUS_PROC_NAMES = {"powershell.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","cmd.exe"}
SUSPICIOUS_KEYWORDS = [" -enc", " -e ", "downloadstring", "invoke-webrequest", "bitsadmin", "frombase64string"]

def _safe_name(p: psutil.Process) -> str:
    try:
        return (p.name() or "").lower()
    except Exception:
        return "unknown"

def _safe_cmd(p: psutil.Process) -> str:
    try:
        return " ".join(p.cmdline()).lower()
    except Exception:
        return ""

def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local)
    except Exception:
        return False

def snapshot_netconns() -> List[NetConnInfo]:
    conns: List[NetConnInfo] = []
    for c in psutil.net_connections(kind="inet"):
        pid = c.pid or 0
        laddr_ip, laddr_port = (None, None)
        raddr_ip, raddr_port = (None, None)
        if c.laddr:
            laddr_ip = c.laddr.ip if hasattr(c.laddr, "ip") else c.laddr[0]
            laddr_port = c.laddr.port if hasattr(c.laddr, "port") else c.laddr[1]
        if c.raddr:
            raddr_ip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
            raddr_port = c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]

        name, cmd = "unknown", ""
        if pid:
            try:
                p = psutil.Process(pid)
                name = _safe_name(p)
                cmd = _safe_cmd(p)
            except Exception:
                pass

        conns.append(NetConnInfo(
            pid=pid,
            laddr=laddr_ip or "",
            raddr=raddr_ip,
            lport=laddr_port,
            rport=raddr_port,
            status=c.status or "",
            proc_name=name,
            cmdline=cmd
        ))
    return conns

def find_suspicious_netconns(conns: List[NetConnInfo]) -> List[NetConnInfo]:
    hits: List[NetConnInfo] = []
    for n in conns:
        # must be outbound to a public IP
        if not n.raddr or not _is_public_ip(n.raddr):
            continue

        low_port_sus = (n.rport in {80, 8080, 53})  # cleartext HTTP/DNS-ish
        proc_sus = (n.proc_name in SUSPICIOUS_PROC_NAMES) or any(k in n.cmdline for k in SUSPICIOUS_KEYWORDS)
        est = n.status.upper() in {"ESTABLISHED", "SYN_SENT"}

        if (proc_sus and est) or (proc_sus and low_port_sus):
            hits.append(n)
    return hits