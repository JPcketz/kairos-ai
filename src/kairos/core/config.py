import yaml
from pathlib import Path
from dataclasses import dataclass

CONFIG_DIR = Path("config")
DEFAULT_CFG = CONFIG_DIR / "kairos.yml"

@dataclass
class AppConfig:
    tier: str
    alerts: dict
    paths: dict

def ensure_default_config() -> Path:
    CONFIG_DIR.mkdir(exist_ok=True)
    if not DEFAULT_CFG.exists():
        DEFAULT_CFG.write_text("""\
tier: basic
alerts:
  email_enabled: false
  sms_enabled: false
  sms_provider: twilio
  sms_from: ""
  sms_to: []
paths:
  logs: "logs"
  reports: "reports"
  cases: "cases"
""", encoding="utf-8")
    return DEFAULT_CFG

def load_config() -> AppConfig:
    ensure_default_config()
    data = yaml.safe_load(DEFAULT_CFG.read_text(encoding="utf-8")) or {}
    return AppConfig(
        tier=data.get("tier","basic"),
        alerts=data.get("alerts",{}),
        paths=data.get("paths",{})
    )