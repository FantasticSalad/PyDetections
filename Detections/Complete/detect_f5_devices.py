# Title: F5 Device Identification via DHCP Lease Activity
# Description: Detects DHCP lease assignments involving MAC address prefixes registered to F5 Networks, in response to F5 Inc. security breach reported on 15/10/25. This detection does not detect malicious activity, instead assists with identifying F5 devices on the network to target for patching and heightened monitoring.
# MITRE Tactic: N/A
# MITRE Technique: N/A
# Log Source: Windows DHCP Server Logs
# Code:

with open("logs/dhcp.txt", "r") as log_file:
    for line in log_file:
        i_list = line.split()
        if len(i_list) < 12:
            continue
        timestamp = " ".join([i_list[0],i_list[1]])
        operation = " ".join([i_list[2],i_list[3],i_list[4],i_list[6],i_list[7]])
        ip_address = i_list[5]
        mac = i_list[8]
        host_name = i_list[11]
        f5_mac_check = i_list[8][:8]
        if f5_mac_check in ("00:01:D7", "00:0A:49", "00:23:E9", "F4:15:63", "00:94:A1", "14:A9:D0"):
            print(f"F5 network device identified in DHCP logs. F5 device details - IP address: {ip_address}. MAC address: {mac}. Host name: {host_name}") 
        