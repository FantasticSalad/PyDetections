# Title: NTDS.dit File Modified
# Description: 
# MITRE Tactic: 
# MITRE Technique: 
# Log Source: 
# Code:

import json

import pprint

with open("logs/win_events_json.txt", "r") as log_file:
    json_logs = log_file.read()
    str_json = json.loads(json_logs)
    for dict in str_json:
        print(dict["computer_name"])
    # pprint.pprint(str_json)