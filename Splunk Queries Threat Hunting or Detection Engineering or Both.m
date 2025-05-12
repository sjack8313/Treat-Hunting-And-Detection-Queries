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


##########################################
# 2. Multiple Failed Logins Followed by Success
# Tags: #DETECTION_ENGINEERING
# Description: Flags brute-force attempts where many failed logins are followed by a success within 15 minutes.
##########################################

index=wineventlog EventCode=4625 OR EventCode=4624
| stats count(eval(EventCode=4625)) as failures, count(eval(EventCode=4624)) as successes by user, src_ip span=15m
| where failures > 10 AND successes > 0


##########################################
# 3. Nmap or Port Scan Behavior
# Tags: #BOTH
# Description: Detects hosts making connections to many different IPs—classic port scanning behavior.
##########################################

index=sysmon EventCode=3
| stats dc(dest_ip) as unique_targets by src_ip
| where unique_targets > 30



##########################################
# 4. RDP Logins Outside of Business Hours
# Tags: #THREAT_HUNTING
# Description: Catches RDP LogonType=10 events happening during unusual hours (before 6am or after 8pm).
##########################################

index=wineventlog EventCode=4624 LogonType=10
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 20
| stats count by user, src_ip

