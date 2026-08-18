# Limitations

Technical honesty is a core principle of ThreatLens: only capabilities that were actually validated with reliable, reproducible evidence are presented as working. This document records what was attempted but **not** included in the validated detection portfolio, and why.

## Documentation Labels Used Throughout This Repository

| Label | Meaning |
|---|---|
| **Validated** | Telemetry directly proves the behavior occurred and the detection fired reliably |
| **Observed in controlled lab** | Activity was intentionally generated in this lab environment — not a real-world compromise |
| **Parked / not included** | Attempted, but not reliably validated — excluded from the capability list below |
| **Hypothesis** | Theoretical reasoning, not yet tested |

## Excluded Experiments

### 1. Active Response — `firewall-drop`

**What was attempted:** Configuring a Wazuh active-response mechanism to automatically drop network connections (`firewall-drop`) tied to a custom detection rule.

**Why it's excluded:** The expected active-response behavior was not reliably validated during testing. Rather than present this as a working automated-response capability, it is documented here as attempted but unconfirmed.

**Status:** Parked.

### 2. Scheduled Task Detection — Rule `100103`

**What was attempted:** A custom Wazuh detection rule targeting suspicious scheduled-task creation (a common persistence/execution technique, MITRE T1053).

**Why it's excluded:** The expected event/alert was not reliably returned when the rule was tested against generated scheduled-task activity.

**Status:** Parked.

## Why These Are Excluded Rather Than "Fixed and Included"

A beginner-level portfolio often claims "I built everything." A more credible SOC portfolio distinguishes between what was implemented *and validated* versus what was investigated but not proven reliable enough to present as a capability. SOC analysts routinely deal with telemetry gaps, detection reliability issues, and the need to validate before trusting a control — this section is meant to reflect that discipline rather than hide it.

## Other Known Scope Boundaries

- All detections were exercised against **intentionally generated** activity in a single-endpoint lab, not against real-world attacker behavior or multiple endpoints.
- The environment does not include network-layer monitoring (e.g. IDS/NDR) — all detections here are host-based (Sysmon/Wazuh Agent/Defender).
- No formal SOAR/ticketing integration was built; investigation output is documentation-based rather than case-management-based.

## Future Work

- Re-attempt Active Response with corrected trigger conditions and confirm block behavior with a controlled test.
- Re-validate scheduled-task detection logic against confirmed Sysmon Event ID 1 telemetry for `schtasks.exe`.
- Extend the lab with a second endpoint to demonstrate lateral-movement detection and cross-host correlation.
