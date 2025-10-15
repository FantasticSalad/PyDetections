# Title: Clearing of event logs using Windows Event Utility
# Description: Checks for attempts to clear at least 10 log entries from event logs using wevtutil. Clearing event logs can be a sign of ransomware activity, as attackers often attempt to cover its tracks by deleting logs.
# MITRE Tactic: DefenseEvasion
# MITRE Technique: T1070
# Log Source: 
# Code:

import re

with open("Logs\\win_process.txt", "r") as log_file:
    for line in log_file:
        i_list = line.strip().split(",")
        timestamp, host, user, child_process, command_line, parent_process, path = i_list[:7]
        parent_process = parent_process.lower
        command_line = command_line.lower
        # if command_line 
        match = re.search(r"^[*]wevtutil\scl[*]", command_line)
        print(match)

# // Look for use of wevtutil to clear multiple logs
# DeviceProcessEvents
# | where TimeGenerated > ago(1h)
# | where ProcessCommandLine has "WEVTUTIL" and ProcessCommandLine has "CL"
# | summarize LogClearCount = dcount(tostring(ProcessCommandLine)), ClearedLogList = make_set(ProcessCommandLine, 100000) by DeviceId, DeviceName, bin(TimeGenerated, 5m)
# | where LogClearCount > 10
# | extend HostName = iff(DeviceName has '.', substring(DeviceName, 0, indexof(DeviceName, '.')), DeviceName)
# | extend DnsDomain = iff(DeviceName has '.', substring(DeviceName, indexof(DeviceName, '.') + 1), "")
