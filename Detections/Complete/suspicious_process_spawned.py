# Title: Suspicious Process Spawned
# Description: Detects suspicious child processes spawned by w3wp.exe, indicating potential webshell activity.
# MITRE Tactic: Execution
# MITRE Technique: T1059 - Command and Scripting Interpreter
# Log Source: Windows Process Logs
# Code:
        
with open("logs/win_process.txt", "r") as logs:
    for line in logs:
        data = line.strip().split(",")
        if len(data) > 5:
            timestamp, host, user, child_process, command_line, parent_process, path = data[:7]
            parent = parent_process.lower()
            child = child_process.lower()
            if parent == "w3wp.exe" and child in (
                "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "pwsh.exe", "wmic.exe", "bitsadmin.exe", "wevtutil.exe", "whoami.exe"
            ):
                print(f"{timestamp}: User {user} utilised {parent_process} to spawn {child_process}, indicating potential suspicious webshell activity on host {host}")