# Title: Multiple MFA Device Registration 
# Description: 
# MITRE Tactic: 
# MITRE Technique: 
# Log Source: 
# Code:

import re
import os

with open("Logs/mfa_registration.txt", "r") as data:
    for line in data:
            line_list = line.strip().split()
            print(line_list)
    
