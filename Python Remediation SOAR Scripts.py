 1. Registry Persistence – T1547.001(SOAR Script)

import winrm

# 1. Establish connection to target host
session = winrm.Session('HOSTNAME_OR_IP', auth=('USERNAME', 'PASSWORD'))

# 2. Delete the registry key (adjust path and key name)
command = r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MaliciousKey /f'
result = session.run_cmd(command)

# 3. Print result for SOAR logging
print(result.std_out.decode())

🔄 Replace on your end:
What to Replace	Example
#'HOSTNAME_OR_IP'	Host from detection (host)
#'USERNAME', 'PASSWORD'	Your admin credentials (or use stored credentials via vault)
#"MaliciousKey"	Key name from detection field RegistryValueName
**********************************
  

 2. OAuth Token Abuse – T1528
import requests

token = "YOUR_ACCESS_TOKEN"
user_id = "USER_ID_FROM_ALERT"

# 1. Revoke sessions (invalidate tokens)
url = f"https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions"
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(url, headers=headers)
print(response.status_code, response.text)

# 2. Reset user password (optional, secure workflow)
# (Requires Graph permission: Directory.AccessAsUser.All)
Replace:
Field	Replace With
YOUR_ACCESS_TOKEN	From your SOAR app integration
user_id	Field from detection (user)
