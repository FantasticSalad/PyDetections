# Title: Suspicious File Download via Certutil URLCache
# Description: Detects suspicious use of certutil.exe to download files via the `-urlcache` option, often leveraged by adversaries for malware delivery or staging.
# MITRE Tactic: Command and Control
# MITRE Technique: T1105 – Ingress Tool Transfer
# Log Source: Windows Process Creation
# Code:


import json
import re

with open("logs/win_process_json.txt", "r") as log_file:
    json_data = json.loads(log_file.read())
    for log in json_data:
        timestamp = log["@timestamp"]
        host = log["computer_name"]
        user = log["user"]["name"]
        
        certutil_check = re.search("(?i)certutil",log["process"]["name"])
        cmdline_check = re.search("(?i)certutil.+urlcache.+?(https?:\/\/\S+)\s+(\S+)",log["process"]["command_line"])
        if certutil_check and cmdline_check:
            print(f"{timestamp}: User {user} utilised certutil.exe to download {cmdline_check.group(2)} from URL {cmdline_check.group(1)}, indicating potential suspicious activity on host {host}")