# Expected detection findings

Per-log, per-detection ground truth. Use to sanity-check after editing a rule: did you change what fires, and was the change intentional?

Lines below are timestamps unless noted. Lines NOT listed under a detection are expected to be benign for that detection.

---

## `win_process.txt`

77 lines total. Two distinct days of activity:
- `2025-10-12` (lines 1-41): original test data covering webshell, log clearing, local admin creation, certutil abuse.
- `2025-11-04` (lines 42-77): browser remote-debugging-port abuse plus benign noise.

### `clear_logs.py` (wevtutil)

Expected to fire on:
- `2025-10-12T08:08:15Z` &mdash; powershell clearing Security log
- `2025-10-12T08:08:45Z` &mdash; cmd clearing System log
- `2025-10-12T08:09:30Z` &mdash; cmd `wevtutil el` (enumerate logs, NOT clear) &mdash; only fires the "unknown logs cleared" branch because the broad `wevtutil\scl` pattern won't match. Verify behaviour.

### `local_admin_creation.py` (net user + add to admins)

Expected to correlate and fire on:
- `tempadmin` &mdash; created 08:10:01, added 08:10:15
- `svc_temp` &mdash; created 08:11:00, added 08:11:15
- `admin2` &mdash; created+added in one powershell line at 08:11:30 (single-line case &mdash; depends on whether your regex handles the combined command)
- `backupadmin` &mdash; created 08:12:00 (net1), added 08:12:15 (net1)

PowerShell variants at 08:10:30 / 08:10:45 (`New-LocalUser`, `Add-LocalGroupMember`) are NOT caught by the current regex (it only matches `net`/`net1`). Known gap.

### `suspicious_process_spawned.py` (w3wp child processes)

Expected to fire on every line where parent is `w3wp.exe` and child is in the watchlist:
- `2025-10-12T08:05:12Z` &mdash; powershell encoded download
- `2025-10-12T08:05:15Z` &mdash; mshta remote HTA
- `2025-10-12T08:08:15Z` &mdash; powershell clearing Security log
- `2025-10-12T08:08:45Z` &mdash; cmd clearing System log
- `2025-10-12T08:11:30Z` &mdash; powershell user creation
- `2025-10-12T08:11:45Z` (wmic with parent cmd.exe NOT w3wp &mdash; does not fire)
- `2025-10-12T08:05:12Z` to `2025-10-12T08:05:15Z` second pair (duplicate block lines 6-7 vs 32+) &mdash; expect duplicate alerts

Note: 7 hits total across the two duplicate blocks.

### `certutil_abuse.py` (urlcache downloads)

Reads JSON file (`win_process_json.txt`), NOT this one. No expected hits here.

### `ntds_file_modified.py`

Reads JSON file (`win_events_json.txt`). No expected hits here.

### `browser_remote_debugging.py` (Draft)

Rule: child process is `chrome.exe`, `msedge.exe`, or `brave.exe`, command line contains `--remote-debugging-port` or `--remote-debugging-pipe`, command line does NOT contain `puppeteer`, `playwright`, or `--remote-debugging-port=0`.

#### True positives (detection fires)

- `2025-11-04T08:43:25Z` mwilliams &mdash; macro-dropped infostealer chain. Word &rarr; encoded powershell &rarr; `updater.exe` &rarr; headless Chrome with `--remote-debugging-port=9222` &rarr; `harvest.py`.
- `2025-11-04T09:17:48Z` dpark &mdash; HTA-dropped attack. mshta.exe spawning headless msedge on port 9223 (non-default port).
- `2025-11-04T09:45:20Z` rgupta &mdash; Brave with `--remote-debugging-pipe`. Parent is rundll32 loading a DLL. Confirms detection covers the pipe variant.
- `2025-11-04T10:41:09Z` mwilliams &mdash; same attacker as 08:43, port 9876 plus `--disable-features=LockProfileCookieDatabase` (the App-Bound Encryption bypass).

Total: 4 alerts.

#### False positives suppressed by the rule (intended)

- `2025-11-04T08:22:33Z` sarah.k &mdash; legitimate Puppeteer dev work. Suppressed by `puppeteer` substring match (command line contains `puppeteer_dev_chrome_profile-abc123`).
- `2025-11-04T10:14:08Z` lwilson &mdash; legitimate Selenium E2E test. Suppressed by `--remote-debugging-port=0` substring match. Port 0 lets Chrome pick a random port, characteristic of test frameworks; attackers almost always pick a specific port.

#### Known coverage gaps

- LOLBin spawners (e.g. `wmic.exe process call create "chrome.exe --remote-debugging-port=..."`) are NOT detected directly: the child_process field records the spawning binary (`wmic.exe`), not the browser. The browser that wmic spawns appears as a separate process-creation event a moment later and would be caught by this rule. Detection of wmic abuse itself is a separate rule (T1047 / T1218).
- Electron app abuse (Slack, Teams, Discord, VS Code) is NOT covered &mdash; their binaries are not in the browser list. Same technique applies; would need a separate rule or a flag-only variant of this rule.
- Firefox uses a different debugging protocol (Marionette / RDP) and is NOT covered &mdash; would need a separate detection.

---

## `dhcp.txt`

### `detect_f5_devices.py`

Fires on every line where the MAC prefix is in the F5 OUI list. Re-check with `grep -cE '(00:01:D7|00:0A:49|00:23:E9|F4:15:63|00:94:A1|14:A9:D0)' Logs/dhcp.txt`.

---

## `syslog.txt`

### `reverse_ssh.py`

Fires on lines matching both `\bssh\b` or `\bautossh\b` AND `\s-R\s`. Exact count: re-derive from current log.

---

## `ssl_toolpane.txt`

### `sharepoint_malicious_post.py`

Fires on tab-separated lines with 9 fields where `http_method=POST`, `request_uri=/_layouts/15/ToolPane.aspx?DisplayMode=Edit`, and `referrer_uri=/_layouts/SignOut.aspx`.

---

## `sysmon_dns.txt`

### `cryptomining_dns.py`

Fires on any line whose JSON `QueryName` matches a known crypto pool domain. Re-derive count from current log.

---

## `win_events_json.txt`

### `ntds_file_modified.py`

Fires on events with `event_id` in (4656, 4663) where `file.object_name` ends with `ntds.dit`.

---

## `win_process_json.txt`

### `certutil_abuse.py`

Fires on events where `process.name` matches `certutil` (case-insensitive) AND `process.command_line` matches the urlcache pattern with extractable URL and filename groups.

---

## Maintenance

When you change a detection rule:
1. Run it.
2. Diff the alerts against the list above.
3. If a known TP stops firing &rarr; regression. Fix.
4. If a new alert appears &rarr; check if it's a known FP from the log, a new TP you intended to add, or a real false positive worth investigating.
5. Update this doc.
