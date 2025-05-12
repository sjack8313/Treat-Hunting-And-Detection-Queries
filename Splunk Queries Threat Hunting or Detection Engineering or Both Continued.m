##########################################
# 5. Suspicious Use of rundll32.exe from Temp Folder
# Tags: #DETECTION_ENGINEERING
# Description:
# rundll32.exe executing from temp directories is often used by malware to execute payloads via LOLBins (Living off the Land Binaries).
# Practical Use:
# Often observed in malware staging, especially when dropped in %Temp% or AppData. Helps in early-stage infection detection.
##########################################

index=sysmon EventCode=1
| search Image="*\\rundll32.exe" CommandLine="*\\AppData\\Local\\Temp*"
| stats count by host, user, CommandLine




##########################################
# 6. DNS Tunneling / High Query Volume
# Tags: #THREAT_HUNTING
# Description:
# Detects hosts making a high number of DNS queries (e.g., >500) — often a sign of DNS tunneling, used for data exfiltration or C2.
# Practical Use:
# Helps uncover stealthy C2 channels and data leaks using DNS, which often bypasses traditional firewalls.
##########################################

index=dns_logs
| stats count by src_ip, query
| where count > 500 AND like(query, "%.%.%") OR like(query, "%-%-%-%")




##########################################
# 7. Office Macro Launch + Network Call
# Tags: #BOTH
# Description:
# Detects Office applications (Word or Excel) executing PowerShell or invoking web-based commands like Invoke-WebRequest or curl.
# Practical Use:
# Used to detect macro-based attacks where Office documents drop or pull payloads. Common in phishing campaigns.
##########################################

index=sysmon ParentImage="*winword.exe" OR ParentImage="*excel.exe"
| search CommandLine="*Invoke-WebRequest*" OR CommandLine="*curl*"
| stats count by user, host, CommandLine



##########################################
# 8. Rare AWS Console Login Location
# Tags: #DETECTION_ENGINEERING
# Description:
# Detects AWS Console logins from more than 3 distinct countries, which may indicate compromised credentials.
# Practical Use:
# Very effective for detecting account takeover in cloud environments, especially with stolen AWS IAM credentials.
##########################################

index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin
| iplocation src_ip
| stats dc(Country) as login_locations by user
| where login_locations > 3


