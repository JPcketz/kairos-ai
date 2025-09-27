rule Test_Suspicious_String
{
  strings: $a = "powershell -enc" ascii nocase
  condition: $a
}