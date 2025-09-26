# Kairos A.I. Containment Playbook — INC-COMPOSITE-1758909603

**Severity:** P2  
**Summary:** 11 recent suspicious file(s) in monitored paths

_Generated: 2025-09-26 13:01:02_

## Scope & Signals

**Files**

- C:\Users\jas06\Downloads\OculusSetup (1).exe (.exe, 4774136 bytes, sha256=f4d758549c5b5873c9e4ab8592c667e05fce0156aa64d8c6bbe28e6382873c2c)
- C:\Users\jas06\Downloads\OculusSetup (2).exe (.exe, 4774136 bytes, sha256=f4d758549c5b5873c9e4ab8592c667e05fce0156aa64d8c6bbe28e6382873c2c)
- C:\Users\jas06\Downloads\OculusSetup (3).exe (.exe, 4774136 bytes, sha256=f4d758549c5b5873c9e4ab8592c667e05fce0156aa64d8c6bbe28e6382873c2c)
- C:\Users\jas06\Downloads\OculusSetup.exe (.exe, 4774136 bytes, sha256=f4d758549c5b5873c9e4ab8592c667e05fce0156aa64d8c6bbe28e6382873c2c)
- C:\Users\jas06\Downloads\urgent_invoice.exe (.exe, 6 bytes, sha256=837ccb607e312b170fac7383d7ccfd61fa5072793f19a25e75fbacb56539b86b)
- C:\Users\jas06\Downloads\VirtualDesktop.Streamer.Setup.exe (.exe, 103585944 bytes, sha256=n/a)
- C:\Users\jas06\Downloads\XboxInstaller.exe (.exe, 14050752 bytes, sha256=n/a)
- C:\Users\jas06\Downloads\VRMark-v1-3-2020\vrmark-setup.exe (.exe, 14793800 bytes, sha256=n/a)
- C:\Users\jas06\Downloads\VRMark-v1-3-2020\redist\dotNetFx45_Full_x86_x64.exe (.exe, 50352408 bytes, sha256=n/a)
- C:\Users\jas06\AppData\Local\Temp\.tmpHK2kDw\applypatch.bat (.bat, 137 bytes, sha256=18a5048e30a52521b4f1e7b87ae341847fbd6a37998d46137b0e9a1862a9d260)
- C:\Users\jas06\AppData\Local\Temp\.tmpHK2kDw\apply_patch.bat (.bat, 137 bytes, sha256=18a5048e30a52521b4f1e7b87ae341847fbd6a37998d46137b0e9a1862a9d260)

## Immediate Actions (Triage)

- Notify on-call (per runbook) and set incident bridge if required.
- Capture volatile data **before** terminating processes if feasible (cmdline, netconns, file paths).
- Validate user/business context for flagged processes or emails.

## File Containment

- Quarantine suspicious files (zip+password or offline share).
- Compute and record hashes (SHA256) for each quarantined file.
- Search for the same hash/path across other endpoints (scope).

## Eradication & Recovery

- Remove persistence artifacts and verify clean startup state.
- Re-image or restore from known-good backups if system integrity is uncertain.
- Monitor closely for reoccurrence (24–72 hours) with tuned detections.

## Documentation

- Update the ticket with actions taken, timelines, indicators, and outcomes.
- Attach artifacts: logs, hashes, screenshots, report PDF.
- Generate and store the Kairos HTML/PDF report with this playbook.

