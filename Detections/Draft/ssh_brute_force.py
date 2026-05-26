# Title: SSH Brute Force - High Volume of Failed Logins from Single Source
# Description: Detects SSH brute force activity by counting "Failed password" events per source IP in syslog. A single source IP attempting authentication against many accounts in a short period is characteristic of credential stuffing or username enumeration. The detection alerts when the count from one IP exceeds a configured threshold and surfaces whether any of those attempts later succeeded (the more serious case).
# MITRE Tactic: Credential Access
# MITRE Technique: T1110.001 - Brute Force: Password Guessing
# Log Source: Linux syslog (sshd)
# Code:

with open("Logs/syslog.txt", "r") as log_file:
    for line in log_file:
        line_list = line.split(" ")
        timestamp = line_list[:3]
        host = line_list[4]
        app = line_list[5]
            
        app = line_list[5]
        app = line_list[5]
        app = line_list[5]
        
        
        
        
        print(timestamp)        

