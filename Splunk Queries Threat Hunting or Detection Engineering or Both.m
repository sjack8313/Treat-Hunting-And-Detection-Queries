##########################################
# 1. Obfuscated PowerShell Commands
# Tags: #BOTH
# Description:
# Detects suspicious PowerShell use with encoded or obfuscated payloads.
# Practical Use:
# Detects initial access, script execution, and payload download tactics using encoded or hidden PowerShell commands.
##########################################

index=windows EventCode=4104 OR EventCode=4688             // Looks for PowerShell script block logging or process execution
| eval PowershellCommand=coalesce(ScriptBlockText, CommandLine)  // Combines both fields into a single command string
| where like(PowershellCommand, "%FromBase64String%")            // Looks for base64 decoding
   OR like(PowershellCommand, "%iex%")                           // Detects Invoke-Expression (used to execute malicious code)
   OR like(PowershellCommand, "%Invoke-WebRequest%")             // Detects network activity for payload downloads
| stats count by user, host, PowershellCommand                   // Aggregates results to show who ran what command


What to replace:

index=windows → Replace with your actual Windows event log index (e.g., index=wineventlog)

ScriptBlockText, CommandLine → Make sure these fields exist in your logs, or adjust based on field names in your environment

user, host → Adjust field names if your data source uses different ones (like UserName, ComputerName)



##########################################
# 2. Multiple Failed Logins Followed by Success
# Tags: #DETECTION_ENGINEERING
# Description:
# Detects brute-force behavior followed by a successful login.
# Practical Use:
# Alerts when an attacker successfully guesses a password after repeated login failures, often a sign of credential compromise.
##########################################

index=wineventlog EventCode=4625 OR EventCode=4624                    // Retrieves failed (4625) and successful (4624) login events
| stats count(eval(EventCode=4625)) as failures,                     // Counts number of failures per user/IP
        count(eval(EventCode=4624)) as successes 
        by user, src_ip span=15m                                     // Aggregates by user and source IP over a 15-minute window
| where failures > 10 AND successes > 0                              // Filters for brute force pattern: 10+ fails followed by a success


What to replace:

index=wineventlog → Your Windows logon events index

user, src_ip → Replace if your environment uses other field names like Account_Name, Source_Network_Address





##########################################
# 3. Nmap or Port Scan Behavior
# Tags: #BOTH
# Description:
# Detects a host scanning many different IPs — typical of port scans or recon.
# Practical Use:
# Detects network reconnaissance activity by tools like Nmap, often part of early attack stages or internal lateral movement.
##########################################

index=sysmon EventCode=3                              // Retrieves network connection events from Sysmon
| stats dc(dest_ip) as unique_targets by src_ip       // Counts how many unique IPs each source IP has connected to
| where unique_targets > 30                           // Filters for hosts making many outbound connections (suspicious scanning)


What to replace:

index=sysmon → Your actual Sysmon index

src_ip, dest_ip → Validate your field names from Sysmon logs (use src_ip, DestinationIp, or similar if different)




##########################################
# 4. RDP Logins Outside of Business Hours
# Tags: #THREAT_HUNTING
# Description:
# Detects RDP sessions initiated during non-work hours.
# Practical Use:
# Unusual RDP logins may indicate lateral movement by threat actors or abuse of admin credentials after hours.
##########################################

index=wineventlog EventCode=4624 LogonType=10          // Finds successful logins over Remote Desktop (LogonType 10)
| eval hour=strftime(_time, "%H")                      // Extracts the hour of the login (00–23)
| where hour < 6 OR hour > 20                          // Flags logins that occur before 6 AM or after 8 PM
| stats count by user, src_ip                          // Groups results by user and IP to identify source of unusual activity

What to replace:

index=wineventlog → Your Windows login index

user, src_ip → Replace with actual field names if needed (e.g., Account_Name, Source_IP)



