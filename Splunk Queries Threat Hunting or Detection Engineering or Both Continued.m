##########################################
# 5. Suspicious Use of rundll32.exe from Temp Folder
# Tags: #DETECTION_ENGINEERING
# Description:
# rundll32.exe running from a temp directory is often used in malware execution.
# Practical Use:
# Identifies malicious payloads dropped to temp folders and executed using LOLBins like rundll32.exe.
##########################################

index=sysmon EventCode=1                                                  // Retrieves process creation events
| search Image="*\\rundll32.exe" CommandLine="*\\AppData\\Local\\Temp*"   // Looks for rundll32.exe launched from a temp path
| stats count by host, user, CommandLine                                  // Shows affected hosts and users running this command





##########################################
# 6. DNS Tunneling / High Query Volume
# Tags: #THREAT_HUNTING
# Description:
# Detects excessive DNS queries with subdomain patterns common in tunneling.
# Practical Use:
# Helps detect stealthy data exfiltration or command-and-control traffic using DNS queries.
##########################################

index=dns_logs                                                         // Searches DNS logs for query activity
| stats count by src_ip, query                                        // Counts number of times each query was made by source IP
| where count > 500 AND (like(query, "%.%.%") OR like(query, "%-%-%-%")) // Filters for high volume and encoded-like query patterns





##########################################
# 7. Office Macro Launch + Network Call
# Tags: #BOTH
# Description:
# Detects Office documents launching commands that reach out to the internet.
# Practical Use:
# Identifies phishing payloads using macros to download malware via curl or PowerShell web requests.
##########################################

index=sysmon ParentImage="*winword.exe" OR ParentImage="*excel.exe"     // Finds processes spawned by Word or Excel
| search CommandLine="*Invoke-WebRequest*" OR CommandLine="*curl*"      // Filters for network calls inside macro-based processes
| stats count by user, host, CommandLine                                // Shows which users and machines executed the network calls




##########################################
# 8. Rare AWS Console Login Location
# Tags: #DETECTION_ENGINEERING
# Description:
# Detects AWS user accounts logging in from many different countries — potential credential compromise.
# Practical Use:
# Flags account takeovers or misuse of IAM credentials across multiple geolocations.
##########################################

index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin       // Looks for AWS login activity from CloudTrail logs
| iplocation src_ip                                              // Performs GeoIP lookup on the source IP
| stats dc(Country) as login_locations by user                   // Counts how many unique countries each user has logged in from
| where login_locations > 3                                      // Flags users with more than 3 distinct login locations



