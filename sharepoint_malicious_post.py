# Title: SharePoint Vulnerability CVE-2025-53771 Attempted Exploit - Malicious Post Request for Auth Bypass
# Description: Detects suspicious POST requests to ToolPane.aspx with a referrer of SignOut.aspx, indicating potential exploitation of CVE-2025-53771 for authentication bypass via crafted session manipulation.
# MITRE Tactic: Initial Access
# MITRE Technique: T1190 - Exploit Public-Facing Application
# Log Source: Web Server SSL Logs (SharePoint/IIS)
# Code:

with open("Logs\\ssl_toolpane.txt", "r") as log_file:
    for line in log_file:
        i_list = line.strip().split("\t")
        if len(i_list) == 9:
            timestamp,host,user,http_method,request_uri,referrer_uri,source_ip,destination_ip,user_agent = i_list[:9]
            if http_method == "POST" and request_uri == "/_layouts/15/ToolPane.aspx?DisplayMode=Edit" and referrer_uri == "/_layouts/SignOut.aspx":
                print(f"{timestamp}: Detected suspicious POST request to ToolPane.aspx from user {user} on host {host}, likely attempting CVE-2025-53771 authentication bypass. Source IP: {source_ip}, Destination IP: {destination_ip}, User-Agent: {user_agent}")