rule HTA_Loader
{
  meta:
    description = "HTA using script engines to execute payloads"
    severity = "medium"
  strings:
    $h1 = "<script language=\"vbscript\"" ascii nocase
    $h2 = "<script language='vbscript'" ascii nocase
    $h3 = "execute(" ascii nocase
    $h4 = "createobject(\"wscript.shell\"" ascii nocase
  condition:
    2 of ($h*)
}

rule VBS_JS_Suspicious_APIs
{
  meta:
    description = "VBS/JS suspicious WScript.Shell & filesystem usage"
    severity = "low"
  strings:
    $v1 = "wscript.shell" ascii nocase
    $v2 = "scripting.filesystemobject" ascii nocase
    $v3 = "run(" ascii nocase
    $v4 = "exec(" ascii nocase
  condition:
    2 of ($v*)
}
powershell
Copy code
