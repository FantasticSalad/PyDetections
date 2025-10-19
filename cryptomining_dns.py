# Title: DNS Query to Cryptomining Pool
# Description: This detection alerts upon DNS query traffic to known cryptomining pools.
# MITRE Tactic: Impact
# MITRE Technique: T1496
# Log Source: Sysmon DNS Logs
# Code:

import json

with open("Logs\\sysmon_dns.txt", "r") as log_file:
    for line in log_file:   
        try:
            json_line = json.loads(line)
            QueryName = json_line["QueryName"]
            if QueryName in (
                    "pool.minexmr.com",
                    "supportxmr.com",
                    "monerohash.com",
                    "xmrpool.eu",
                    "nanopool.org",
                    "minexmr.com",
                    "dwarfpool.com",
                    "hashcity.org",
                    "f2pool.com",
                    "ethermine.org",
                    "ethpool.org",
                    "sparkpool.com",
                    "2miners.com",
                    "minergate.com",
                    "slushpool.com",
                    "btc.com",
                    "antpool.com",
                    "viabtc.com",
                    "poolin.com",
                    "binancepool.com",
                    "luxor.tech",
                    "prohashing.com",
                    "nicehash.com",
                    "uupool.cn",
                    "bwpool.net",
                    "rawpool.com",
                    "dwmxmr.com",
                    "hashvault.pro"
            ):
                print(f"{json_line["UtcTime"]}: Process at path {json_line["Image"]} initiated a DNS query to {json_line["QueryName"]}, a known crypto mining domain. User: {json_line["UserID"]}.")
        except json.JSONDecodeError as error:
            print(f"Failed to parse line: {error}")