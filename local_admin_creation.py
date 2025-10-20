# Title: 
# Description: 
# MITRE Tactic: 
# MITRE Technique: 
# Log Source: 
# Code:

import re

with open("Logs\\win_process.txt", "r") as log_file:
    for line in log_file:
        i_list = line.strip().split(",")
        if len(i_list) < 7:
            continue
        timestamp, host, user, child_process, command_line, parent_process, path = i_list[:7]
        net_check_match = re.search(r"\^net", command_line)
        if net_check_match:
            print(i_list)
        
        
    


# 2025-10-12T08:10:30Z,web01,svc_webapp,powershell.exe,"powershell New-LocalUser -Name tempadmin -Password (ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force)",explorer.exe,"explorer.exe",C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,Yes,1
# 2025-10-12T08:10:45Z,web01,svc_webapp,powershell.exe,"powershell Add-LocalGroupMember -Group 'Administrators' -Member 'tempadmin'",explorer.exe,"explorer.exe",C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,Yes,1
