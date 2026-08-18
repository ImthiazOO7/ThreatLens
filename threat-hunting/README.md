# Threat Hunting

ThreatLens doesn't rely solely on "wait for Wazuh to generate an alert." It also demonstrates **proactive threat hunting** — searching collected telemetry for suspicious patterns before (or independent of) an alert firing.

## Alert-driven vs. hunt-driven workflows

```
Alert-driven:              Alert → Investigate

Hunt-driven:  Hypothesis → Search telemetry → Find suspicious patterns
                              → Investigate → Determine malicious/benign
```

The hunt-driven model is the more mature SOC workflow, because it doesn't depend on a rule already existing for the behavior you're looking for.

## What was used

Wazuh's threat-hunting/event views were used to inspect:

- Alerts across the environment
- MITRE ATT&CK mappings
- Registered agents
- Event timelines
- Rule IDs and severities
- Process activity and endpoint behavior

For example, the MITRE-enriched event view was filtered using queries such as:

```
manager.name: ubuntu-server
rule.mitre.id: exists
```

This surfaces every event across the environment that has been enriched with a MITRE ATT&CK technique, giving a broad view of adversary-relevant activity rather than only what a specific rule happened to catch.

## Where this fits in the project

- Methodology: [`hunting-methodology.md`](hunting-methodology.md)
- Hypotheses tested: [`hypotheses.md`](hypotheses.md)

## Relationship to the dashboard

The Wazuh Dashboard (see [`dashboards/`](../dashboards/README.md)) answers *"what is happening across the environment?"* Threat hunting goes a step further and asks *"is there anything happening here that I should be looking for, even if nothing has alerted on it yet?"*

## Evidence

- `evidence/threat-hunting-events.png` — Wazuh's Threat Hunting Events view, filtered to `manager.name: ubuntu-server`, showing 525 hits over the last 24 hours with rule description and severity level visible — this is the raw event-search interface used to run the hunts described in `hunting-methodology.md`
