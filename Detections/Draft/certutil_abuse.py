# Title: Certutil
# Description: 
# MITRE Tactic: 
# MITRE Technique: 
# Log Source: 
# Code:

import json
import pprint
import re

with open("logs/win_process_json.txt", "r") as log_file:
    json_data = json.loads(log_file.read())
    pprint.pprint(json_data)
    for log in json_data:
        certutil_check = re.search("(?i)certutil",log["process"]["name"])
        cmdline_check = re.search("(?i)certutil.+urlcache.+?(https?:\/\/\S+)\s+(\S+)",log["process"]["command_line"])
        print(cmdline_check.group)