# Title: 
# Description:
# MITRE Tactic:
# MITRE Technique:
# Log Source:
# Code:

with open("Logs\\win_process_logs.txt", "r") as logs:
    for line in logs:
        data = line.split(",")
        if data[4] in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "pwsh.exe", "wmic.exe", "bitsadmin.exe"):
            print(data)
        
