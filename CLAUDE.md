# PyDetections — Claude context

**This repo is public.** Anything committed here is published: no secrets, no
machine paths or usernames, no client or employer names, no private notes.

## What it is

Threat-led detections in plain Python, each run against sample logs in `Logs/`.
Stdlib only (`json`, `re`); no dependencies, no venv, no test framework.

- `Detections/Complete/` — validated detections. One script per detection.
- `Detections/Draft/` — works in progress, not validated. May not run.
- `Logs/` — synthetic sample logs. `Logs/_expected.md` is the ground truth:
  which lines each detection should and should not fire on, including known gaps.

Every detection starts with the header block described in `README.md`
(Title, Description, MITRE Tactic, MITRE Technique, Log Source, Code). Keep it.

## Rules

- **The detections are hand-written, and the README says so.** Don't rewrite
  detection logic unless asked. Review comments and suggestions are fine;
  unrequested refactors are not.
- The sample logs were AI-generated (README "On AI use"). Changing a log
  changes what fires, so update `Logs/_expected.md` in the same commit.
- Copy is plain practitioner language, and describes detections from the
  defender's side.

## Checking a change

Run from the repo root, because scripts open logs by relative path:

```sh
for f in Detections/Complete/*.py; do python "$f" > /dev/null || echo "FAIL $f"; done
```

Then compare the output of the detection you touched against its section in
`Logs/_expected.md`.

## Known issues

- **Log paths only work on Windows.** Several scripts open `Logs\file.txt`
  (backslash) or `logs/file.txt` (the folder is `Logs`). Windows accepts both,
  but on Linux and macOS those scripts fail with `FileNotFoundError`, although
  the README tells readers to clone and run. The fix is to use `Logs/<file>`
  everywhere (forward slash, capital L). It touches every detection, so it
  waits for the owner. `[needs James — found by Autopilot 2026-09-17]`
- `Detections/Draft/a_template_for_detections copy 3.py` has spaces in its name
  and looks like a leftover copy.
