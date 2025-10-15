# Title: Malicious Webcall Intiated by Microsoft Office Application
# Description: 
# MITRE Tactic: 
# MITRE Technique: 
# Log Source: 
# Code:

with open("Logs\\sysmon_dns.txt","r") as log_text:
    for line in log_text:
        
        # print(type(line))
        print(log_text.read())
    
