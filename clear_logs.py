# Title: Clearing of event logs using Windows Event Utility
# Description: Checks for attempts to clear log entries from event logs using wevtutil. Clearing event logs can be a sign of ransomware activity, as attackers often attempt to cover its tracks by deleting logs.
# MITRE Tactic: DefenseEvasion
# MITRE Technique: T1070
# Log Source: Windows Process Logs
# Code:

import re

with open("Logs\\win_process.txt", "r") as log_file:
    for line in log_file:
        i_list = line.strip().split(",")
        if len(i_list) < 7:
            continue
        timestamp, host, user, child_process, command_line, parent_process, path = i_list[:7]
        parent_process = parent_process.lower()
        command_line = command_line.lower()
        wev_match = re.search(r"wevtutil\scl", command_line)
        if wev_match: 
            sec_log_match = re.search(r"wevtutil\scl\ssecurity", command_line)
            system_log_match = re.search(r"wevtutil\scl\ssystem", command_line)
            app_log_match = re.search(r"wevtutil\scl\sapplication", command_line)
            setup_log_match = re.search(r"wevtutil\scl\ssetup", command_line)
            if sec_log_match:
                print(f"{timestamp}: Detected security logs cleared using wevtutil.exe by {user} on host {host}. Command line: {command_line}))")
            if system_log_match:
                print(f"{timestamp}: Detected system logs cleared using wevtutil.exe by {user} on host {host}. Command line: {command_line}))")
            if app_log_match:
                print(f"{timestamp}: Detected application logs cleared using wevtutil.exe by {user} on host {host}. Command line: {command_line}))")
            if setup_log_match:
                print(f"{timestamp}: Detected setup logs cleared using wevtutil.exe by {user} on host {host}. Command line: {command_line}))")
            if not any([sec_log_match, system_log_match, app_log_match, setup_log_match]):
                print(f"{timestamp}: Detected unknown logs cleared using wevtutil.exe by {user} on host {host}. Command line: {command_line}")   