# Title: 
# Description: 
# MITRE Tactic: 
# MITRE Technique: 
# Log Source: 
# Code:

import re

with open("logs/syslog.txt", "r") as log_file:
    for line in log_file:
        i_list = line.split()
        print(len(i_list))
        if len(i_list) < 5:
            continue
        timestamp = " ".join([i_list[0],i_list[1],i_list[2]])
        hostname = i_list[3]
        process = i_list[4][:-1]
        message = " ".join(i_list[5:])
        command = message[4:]
        
        ssh_check = re.search(r"(\bssh\b|\bautossh\b)", command)
        
        r_check = re.search(r"\b-R\b", command, re.IGNORECASE)
        
        print(f"{ssh_check}, {r_check}")
        
        # print(f"{timestamp}: {message}. Host: {hostname}, Process: {process}")
        
        # print(f"MESSAGE: {message}")
        
        print(f"COMMAND: {command}")
        
        # operation = " ".join([i_list[2],i_list[3],i_list[4],i_list[6],i_list[7]])
        # ip_address = i_list[5]
        # mac = i_list[8]
        # host_name = i_list[11]
        # f5_mac_check = i_list[8][:8]