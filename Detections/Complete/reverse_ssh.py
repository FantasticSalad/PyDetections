# Title: SSH Reverse Tunnel
# Description: Identifies potential reverse SSH tunneling activity by detecting use of 'ssh' or 'autossh' with the '-R' flag in linux command line.
# MITRE Tactic: Command and Control
# MITRE Technique: T1219 - Remote Access Software
# Log Source: Syslog
# Code:

import re

with open("logs/syslog.txt", "r") as log_file:
    for line in log_file:
        i_list = line.split()
        # print(len(i_list))
        if len(i_list) < 5:
            continue
        timestamp = " ".join([i_list[0],i_list[1],i_list[2]])
        hostname = i_list[3]
        process = i_list[4][:-1]
        message = " ".join(i_list[5:])
        command = message[4:]
        # search for ssh and -R flag
        ssh_check = re.search(r"(\bssh\b|\bautossh\b)", command,re.IGNORECASE)
        r_check = re.search(r"\s-R\s", command, re.IGNORECASE)
        if ssh_check and r_check:
            print(f"{timestamp}: {message}. Host: {hostname}, Process: {process}")