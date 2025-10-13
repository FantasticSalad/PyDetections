# Title: Suspicious Webshell Spawned
# Description: Detects suspicious child processes spawned by w3wp.exe, indicating potential webshell activity.
# MITRE Tactic: Execution
# MITRE Technique: T1059 - Command and Scripting Interpreter
# Log Source: Windows Process Logs
# Code:

with open("Logs\\win_process_logs.txt", "r") as logs:
    for line in logs:
        data = line.strip().split(",")
        if len(data) > 5: # check parent_process exists
            timestamp = data[0]
            host = data[1]
            user = data[2]
            child_process = data[3]
            # command_line = data[4]
            parent_process = data[5]
            # parent_command_line = data[6]
            # path = data[7]
            # network_activity = data[8]
            if parent_process.lower() == "w3wp.exe" and child_process.lower() in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "pwsh.exe", "wmic.exe", "bitsadmin.exe","wevtutil.exe","whoami.exe"):
                print(f"{timestamp}: User {user} utilised {parent_process} to spawn {child_process}, indicating potential suspicious webshell activity on host {host}")

        
