rule LOLBIN_Command_Hints
{
  meta:
    description = "References to common LOLBIN patterns"
    severity = "low"
  strings:
    $l1 = "rundll32.exe" ascii nocase
    $l2 = "mshta.exe" ascii nocase
    $l3 = "regsvr32 /i:" ascii nocase
    $l4 = "wmic process call create" ascii nocase
    $l5 = "schtasks /create" ascii nocase
  condition:
    any of ($l*)
}