import os
from typing import Sequence
from twilio.rest import Client
from .base import Notifier, comma_list

class TwilioSMS(Notifier):
    def __init__(self, from_number: str, to_numbers: Sequence[str]):
        self.from_number = from_number
        self.to_numbers = list(to_numbers)
        # Read creds from env only (keep secrets out of disk)
        self.sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
        self.token = os.environ.get("TWILIO_AUTH_TOKEN", "")
        if not self.sid or not self.token:
            raise RuntimeError("Twilio credentials not set in environment variables: TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN")

        self.client = Client(self.sid, self.token)

    def notify(self, subject: str, body: str) -> None:
        text = f"[Kairos] {subject}\n{body}"
        for dest in self.to_numbers:
            self.client.messages.create(
                from_=self.from_number,
                to=dest,
                body=text[:1590]
            )

def build_from_env_and_config(cfg_alerts: dict):
    """
    Build TwilioSMS using env as primary source, falling back to config for numbers.
    """
    from_number = os.environ.get("KAIROS_SMS_FROM") or cfg_alerts.get("sms_from") or ""
    to_numbers = comma_list(os.environ.get("KAIROS_SMS_TO") or ",".join(cfg_alerts.get("sms_to", [])))
    if not from_number or not to_numbers:
        raise RuntimeError("SMS from/to not configured. Set KAIROS_SMS_FROM/KAIROS_SMS_TO or alerts.sms_from/sms_to.")
    return TwilioSMS(from_number, to_numbers)