from abc import ABC, abstractmethod
from typing import Sequence

class Notifier(ABC):
    @abstractmethod
    def notify(self, subject: str, body: str) -> None:
        ...

def comma_list(val: str | None) -> list[str]:
    if not val:
        return []
    return [x.strip() for x in val.split(",") if x.strip()]

def redact(s: str, keep: int = 4) -> str:
    if not s:
        return ""
    return ("*" * max(0, len(s) - keep)) + s[-keep:]