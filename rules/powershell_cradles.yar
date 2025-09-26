rule PS_Base64_Or_IEX
{
  meta:
    description = "PowerShell base64 or IEX usage"
    severity = "medium"
  strings:
    $a1 = "powershell -enc" ascii nocase
    $a2 = "frombase64string(" ascii nocase
    $a3 = "iex(" ascii nocase
    $a4 = "invoke-expression" ascii nocase
  condition:
    any of ($a*)
}

rule PS_Web_Download
{
  meta:
    description = "PowerShell web download primitives"
    severity = "medium"
  strings:
    $b1 = "invoke-webrequest" ascii nocase
    $b2 = "system.net.webclient" ascii nocase
    $b3 = "downloadstring(" ascii nocase
    $b4 = "downloadfile(" ascii nocase
    $b5 = "bitsadmin" ascii nocase
  condition:
    any of ($b*)
}