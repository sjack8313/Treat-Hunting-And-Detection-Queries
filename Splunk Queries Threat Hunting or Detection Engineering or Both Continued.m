#7 - Office Macro Launch + Network Call
What it Detects:
Phishing emails that drop Word or Excel docs with malicious macros that run PowerShell (Invoke-WebRequest) to download payloads.

SPL:

index=sysmon ParentImage="*winword.exe" OR ParentImage="*excel.exe"
| search CommandLine="*Invoke-WebRequest*" OR CommandLine="*curl*"
| stats count by user, host, CommandLine
What to Replace:

index=sysmon ➜ Replace with the actual index your org stores Sysmon logs in (could be windows_logs, endpoint, etc.)

ParentImage="*winword.exe" ➜ Keep this unless your telemetry uses different casing or log format

CommandLine=... ➜ You can expand this with other network utilities used in attacks like bitsadmin, wget, etc.

********************************************************************************************************************************************

✅ #8 - Rare AWS Console Login Locations
What it Detects:
Potential IAM account misuse — login from >3 countries could be credential theft or token misuse.

SPL:
index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin
| iplocation src_ip
| stats dc(Country) as login_locations by user
| where login_locations > 3
What to Replace:

index=aws ➜ Replace with your actual AWS CloudTrail index name

src_ip ➜ Must match the field in your logs that holds the login IP (sometimes sourceIPAddress)

user ➜ Ensure it matches your CloudTrail username field (often userIdentity.arn or userIdentity.userName)

********************************************************************************************************************************************

✅ #6 - DNS Tunneling / High Query Volume
What it Detects:
Suspicious DNS activity — high volume or subdomain-heavy queries are often signs of data exfiltration via DNS tunneling.

SPL:
index=dns_logs
| stats count by src_ip, query
| where count > 500 AND (like(query, "%.%.%") OR like(query, "%-%"))
What to Replace:

index=dns_logs ➜ Replace with your DNS log index (dns, infoblox, etc.)

src_ip ➜ Could be client_ip, src, etc., depending on your logging

query ➜ Might be domain, question.name, etc.

