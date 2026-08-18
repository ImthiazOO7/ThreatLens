# Lessons Learned

## 1. Telemetry quality determines investigation quality

Native Windows Event Logs alone weren't detailed enough to build the investigations in this repository. Sysmon's process GUIDs, parent/child relationships, full command lines, and hashes are what actually made correlation (e.g. IR-001's process → file-creation link) possible. The lesson: invest in telemetry fidelity *before* writing detection logic — a great rule against weak data still produces a weak alert.

## 2. Legitimate tools are the hardest detections to get right

All three validated detections (`net.exe`, PowerShell, Registry Run keys) are built on tools Windows itself relies on constantly. Writing a rule that fires reliably is the easy part; writing false-positive analysis that an analyst can actually use to triage quickly is the harder, more valuable part. This shaped the decision to document false-positive context for every single detection rather than treating that as optional.

## 3. A dashboard is not an investigation

Early in the project it was tempting to treat the Wazuh dashboard's event counts and MITRE views as "proof" of findings. They're not — they answer *"what's happening across the environment,"* not *"what does this specific alert mean."* That distinction is why this repository separates `dashboards/` (environment-wide monitoring) from `investigations/` (specific, evidence-backed cases) as different things entirely.

## 4. Correlation is a skill, not a feature

Wazuh generating an alert is a starting point, not an endpoint. The most valuable part of IR-001 wasn't the PowerShell alert itself — it was pivoting from that alert to the related file-creation event using shared process identifiers and timestamp proximity. That pivot is the actual analyst work; the alert is just the trigger for it.

## 5. Knowing what to leave out matters as much as what to include

Two experiments — Active Response (`firewall-drop`) and the scheduled-task detection (Rule `100103`) — didn't produce reliable results. The instinct might be to include them anyway with generous framing. Instead they were parked and explicitly documented as unvalidated (see [`limitations.md`](limitations.md)). A portfolio that says "these worked, these didn't, here's why" is more credible than one that claims everything worked.

## 6. EICAR is a validation test, not a war story

It would be easy to frame the EICAR/Defender detection as "detected and stopped malware." That's not accurate — EICAR is a designed-to-be-harmless industry test string. Framing it honestly, as endpoint-protection validation rather than a threat response, was a deliberate choice to keep the whole project technically credible.

## 7. Documentation is part of the deliverable, not an afterthought

A working detection that isn't documented (data source, MITRE mapping, false-positive reasoning, investigation steps) is much less useful — both operationally and as a portfolio piece — than a documented one. Structuring evidence *beside* the detection or investigation it supports (rather than a flat `screenshots/` folder) was a deliberate decision to make the repository readable as a real case file, not a slideshow.
