# Title: Local Admin Creation
# Description: Detects creation of local user accounts followed by their addition to the Administrators group, using either net.exe/net1.exe or PowerShell cmdlets.
# MITRE Tactic: Privilege Escalation, Persistence
# MITRE Technique: T1136.001 (Create Account: Local Account), T1078.004 (Valid Accounts: Local Accounts)
# Log Source: Windows Process Execution Logs
# Code:

import re

accounts_created = []

with open("Logs\\win_process.txt", "r") as log_file:
    for line in log_file:
        i_list1 = line.strip().split(",")
        if len(i_list1) < 7:
            continue
        timestamp1, host1, user1, child_process1, command_line1, parent_process1, path1 = i_list1[:7]
        command_line1= command_line1.strip("\"")
        net_user_match = re.search(r"net1?\suser\s(\S+)", command_line1)
        if net_user_match:
            accounts_created.append(net_user_match.group(1))
    log_file.seek(0)
    for line in log_file:
        i_list2 = line.strip().split(",")
        if len(i_list2) < 7:
            continue
        timestamp2, host2, user2, child_process2, command_line2, parent_proces2, path2 = i_list2[:7]
        command_line2 = command_line2.strip("\"")
        add_admin_match = re.search(r"net1?\slocalgroup\sadministrators\s(\S+)", command_line2)
        if add_admin_match and add_admin_match.group(1) in accounts_created:
                print(f"Detected creation of local admin account \"{add_admin_match.group(1)}\" using {child_process2} on host {host2}. \n{timestamp1}: Local admin user creation command line: {command_line1} \n{timestamp2}: Account added to administrators group command line: {command_line2}\n")
