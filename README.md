# Kairos A.I. — SOC Sidekick (MVP)

Kairos is a local-first assistant for SOC analysts and ethical hackers. It **finds**, **assesses**, and **guides containment** so humans can keep working instead of drowning in paperwork. It runs on the client’s machine — no data leaves by default.

---

## ✨ Features (MVP)
- **Processes** with parent→child chains (e.g., `winword.exe → powershell.exe`)
- **Network** snapshot (risky procs → public IP / cleartext ports like 80/8080/53)
- **Filesystem sweep** (Downloads / Temp / Startup; hashes small files)
- **Email intake** (local `.eml` + optional IMAP), URL/attachment heuristics
- **Persistence sweep** (Run / RunOnce, Scheduled Tasks, Services)
- **Policy engine** (allow/deny lists; thresholds; P5 suppression)
- **Optional YARA** on suspicious files (`rules/*.yar`)
- **Reports**: HTML + PDF + containment **playbook.md** + **ticket.txt**
- **Handoff bundle**: ZIP with everything; **P1 SMS** via Twilio (opt-in)

---

## 🚀 Quickstart (Windows PowerShell)
```pwsh
# 1) Create venv and install
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

# 2) Initialize config then run a dry scan
kairos --init
kairos scan --dry

# 3) Generate artifacts
kairos report --open    # HTML
kairos pdf              # PDF
kairos playbook --open  # Markdown playbook + ticket text
kairos bundle           # ZIP with all outputs
Outputs land in logs\incidents\ (JSON) and reports\ (HTML/PDF/MD/TXT/ZIP).

⚙️ Configuration (config/kairos.yml)
Key sections:

yaml
Copy code
paths:
  logs: "logs"
  reports: "reports"

alerts:
  email_enabled: false
  sms_enabled: false       # set true or use --enable-sms
  sms_provider: twilio
  sms_from: ""             # prefer env var KAIROS_SMS_FROM
  sms_to: []               # prefer env var KAIROS_SMS_TO (comma-sep)

email:
  enabled: false
  imap_host: ""            # e.g., outlook.office365.com
  imap_port: 993
  folder: "INBOX"
  max_messages: 10
  local_eml_dir: "mailbox" # drop .eml files here for offline tests

policy:
  thresholds:
    p1_min_types: 2        # how many signal types → P1
    suppress_p5: true
  allow:
    process_names: []
    paths: []
    ips_or_domains: []
  deny:
    process_cmdline_keywords: [" -enc", "downloadstring", "invoke-webrequest", "bitsadmin"]
    file_exts: [".ps1",".vbs",".js",".jse",".wsf",".hta",".bat",".cmd",".lnk",".dll",".exe",".scr"]

yara:
  enabled: false           # flip to true to enable
  rules_dir: "rules"
  max_size_bytes: 10485760
Secrets via ENV (recommended)

Twilio: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, KAIROS_SMS_FROM, KAIROS_SMS_TO (comma-sep)

IMAP: KAIROS_IMAP_USER, KAIROS_IMAP_PASS

🔍 Typical Workflow
kairos scan --dry — create a new incident JSON.

kairos report --open — see artifacts & recommendations.

kairos pdf — make a client-friendly PDF.

kairos playbook --open — step-by-step containment + ticket text.

(Optional) --enable-sms + env creds → P1 SMS.

kairos bundle — ZIP everything for handoff.

🧪 YARA (optional)
Enable in config (yara.enabled: true).

Put rules in rules\*.yar. Example:

yar
Copy code
rule PS_Web_Download { strings: $a="invoke-webrequest" ascii nocase condition: $a }
Files matched: whatever the filesystem sweep finds (e.g., .ps1, .vbs, .js, .exe if small).

🧰 Troubleshooting
IndentationError in CLI: you likely mixed tabs/spaces. Re-paste src\kairos\main.py from repo.

Twilio send fails: check env vars; try kairos scan --enable-sms --dry to simulate.

IMAP errors: it’s optional. Drop .eml into mailbox\ and run again.

No outputs: ensure you ran kairos scan before report/pdf/playbook/bundle.

📜 License
MIT (see LICENSE).

🙌 Credits
Kairos A.I. — designed to be a pragmatic SOC sidekick.