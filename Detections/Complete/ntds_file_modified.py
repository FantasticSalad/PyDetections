# Title: NTDS.dit Active Directory Database File Modified
# Description: Detects access or modification attempts to the Active Directory database file (ntds.dit), which may indicate credential theft or domain replication activity.
# MITRE Tactic: Credential Access
# MITRE Technique: T1003.003 – OS Credential Dumping: NTDS
# Log Source: Windows Security Event Logs
# Code:

import json
import re

with open("logs/win_events_json.txt", "r") as log_file:
    json_logs = log_file.read()
    str_json = json.loads(json_logs)
    for dict in str_json:
        try:
            ntds_check = dict["file"]["object_name"].lower()
        except KeyError:
            continue
        if dict["event_id"] in (4656, 4663) and re.search("ntds.dit$", ntds_check):
            print(f"{dict["@timestamp"]}: User {dict["user"]["name"]} attempted to modify the Active Directory database file, ntds.dit, utilising process {dict["file"]["process_name"]} indicating potential attempted credential theft or domain replication. Host: {dict["computer_name"]}, Windows Event Code: {dict["event_id"]}, Event Type: {dict["event_type"]}")