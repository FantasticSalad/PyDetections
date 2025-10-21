# Title: Local Admin Creation
# Description: 
# MITRE Tactic: 
# MITRE Technique: 
# Log Source: 
# Code:

import re

accounts_created = []


with open("Logs\\win_process.txt", "r") as log_file:
    for line in log_file:
        i_list = line.strip().split(",")
        if len(i_list) < 7:
            continue
        timestamp, host, user, child_process, command_line, parent_process, path = i_list[:7]
        command_line = command_line.strip("\"")
        net_user_match = re.search(r"net1?\suser\s(\S+)", command_line)
        # print(command_line)
        if net_user_match:
            accounts_created.append(net_user_match.group(1))
        # if net_user_match:
        #     print(i_list)
    for line in log_file:
        i_list_a = line.strip().split(",")
        if len(i_list_a) < 7:
            continue
        timestamp, host, user, child_process, command_line, parent_process, path = i_list[:7]
        command_line = command_line.strip("\"")
        add_admin_match = re.search(r"net1?\slocalgroup\sadministrators\s(\S+)", command_line)
        print(add_admin_match)
        # if add_admin_match.group(1) in accounts_created:
        #     print(i_list_a)
        
        
# print(accounts_created)
    


# 2025-10-12T08:10:30Z,web01,svc_webapp,powershell.exe,"powershell New-LocalUser -Name tempadmin -Password (ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force)",explorer.exe,"explorer.exe",C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,Yes,1
# 2025-10-12T08:10:45Z,web01,svc_webapp,powershell.exe,"powershell Add-LocalGroupMember -Group 'Administrators' -Member 'tempadmin'",explorer.exe,"explorer.exe",C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,Yes,1
