# Title: Browser Remote Debugging Port Abuse for Cookie and Session Theft
# Description: Detects Chromium-based browsers launched with the --remote-debugging-port flag, a technique used by infostealers (LummaC2, Stealc) to bypass App-Bound Encryption introduced in Chrome 127+. The attacker spawns the browser against a copy of the victim's profile and connects to the DevTools Protocol websocket to extract decrypted cookies and session tokens in-process, sidestepping the encryption that protects cookies at rest.
# MITRE Tactic: Credential Access
# MITRE Technique: T1555.003 - Credentials from Password Stores: Credentials from Web Browsers
# Log Source: Windows Process Execution Logs
# Code:

with open("logs/win_process.txt", "r") as log_file:
    for line in log_file:
        data=line.strip().split(",")
        if len(data) < 7:
            continue
        timestamp, host, user, child_process, command_line, parent_process, path = data[:7]
        if (
            child_process.lower() in ('msedge.exe', 'brave.exe', 'chrome.exe')
            and ("--remote-debugging-port" in command_line or "--remote-debugging-pipe" in command_line)
            and not ("puppeteer" in command_line or "playwright" in command_line or "--remote-debugging-port=0" in command_line)
        ):
            print(f"{timestamp}: Detected potential browser cookie/session theft. {child_process} launched on host {host} by user {user} with remote debugging flag, indicating possible exploitation of Chrome DevTools Protocol for credential extraction (T1555.003). Command line: {command_line}. Parent process: {parent_process}\n")