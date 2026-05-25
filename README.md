# PyDetections

Threat-led detections written in Python, each tested against sample logs included in the repo.

## What's here

Each detection in `Detections/Complete/` is a self-contained script that reads a log file, applies parsing and matching logic, and prints an alert when it triggers. Detections cover techniques across the MITRE ATT&CK matrix: credential access, defence evasion, command and control, execution, persistence, initial access. Some respond to specific incidents (the SharePoint ToolPane.aspx exploit, the F5 breach disclosure); others target durable adversary behaviour (NTDS.dit access, log clearing via wevtutil, reverse SSH tunnels, certutil downloads).

Every detection follows the same header format:

```
# Title:
# Description:
# MITRE Tactic:
# MITRE Technique:
# Log Source:
# Code:
```

Drafts sit in `Detections/Draft/`. Works in progress, not yet validated.

## How to run

Stdlib only (`json`, `re`). No virtualenv or dependencies required.

```
git clone https://github.com/FantasticSalad/PyDetections.git
cd PyDetections
python Detections/Complete/sharepoint_malicious_post.py
```

Each detection reads from `Logs/` via relative path, so run from the repo root.

## Repo layout

```
PyDetections/
&#9500;&#9472;&#9472; Detections/
&#9474;   &#9500;&#9472;&#9472; Complete/        # validated detections
&#9474;   &#9492;&#9472;&#9472; Draft/           # in progress
&#9492;&#9472;&#9472; Logs/                # sample logs the detections parse
```

## On AI use

AI was used minimally for code review and generating the sample logs in `Logs/`. The detections were written by hand.

## Contact

[linkedin.com/in/bullen](https://www.linkedin.com/in/bullen/)
