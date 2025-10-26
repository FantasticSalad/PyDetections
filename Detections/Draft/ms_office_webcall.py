# Title: Malicious Webcall Intiated by Microsoft Office Application
# Description: 
# MITRE Tactic: 
# MITRE Technique: 
# Log Source: 
# Code:

import json

with open("Logs\\sysmon_dns.txt","r") as log_file:
    for line in log_file:   
        try:
            json_line = json.loads(line)
            QueryName = json_line["QueryName"]
        except json.JSONDecodeError as error:
                    print(f"Failed to parse line: {error}")
        print(log_file.read())