##########################################
# 1. Obfuscated PowerShell Commands
# Tags: #BOTH
# Description: Detects suspicious PowerShell use with encoded commands, such as base64 or IEX.
# Useful for catching initial execution or payload download techniques.
##########################################

index=windows EventCode=4104 OR EventCode=4688
| eval PowershellCommand=coalesce(ScriptBlockText, CommandLine)
| where like(PowershellCommand, "%FromBase64String%") 
  OR like(PowershellCommand, "%iex%") 
  OR like(PowershellCommand, "%Invoke-WebRequest%")
| stats count by user, host, PowershellCommand

