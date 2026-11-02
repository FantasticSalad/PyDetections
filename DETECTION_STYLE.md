# Python detection target

Inherits the common requirements of a shared detection standard, revision 2026-11-02.1,
which is maintained outside this repository and is not public. This is authoring
guidance, not a runtime dependency for running the scripts.

## Artifact format

Keep the Python comment header in [README.md](README.md): Title, Description, MITRE
Tactic, MITRE Technique, Log Source and Code. Keep plain Python implementations and the
synthetic-log ground truth. XQL stages, plain-XQL metadata labels, Cortex issue mappings,
cron and suppression configuration are outside this target's artifact format.

## Additions and exceptions

No current presentation overrides of the applicable common principles. Preserve each
hand-written detection and its logic unless a task explicitly authorises a change.
Put standard revision, reviewed artifact revision and any rule exception in separate
review notes. General style recommendations go to the shared standard; repo-specific
packaging recommendations go here; rule-specific reasoning stays beside that rule.
Each accepted override records its convention, difference, reason, authority and review
condition. Existing rules have not been re-reviewed merely because this pointer was added.
