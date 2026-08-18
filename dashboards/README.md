# SOC Dashboard

The Wazuh Dashboard provides the high-level, environment-wide operational view of ThreatLens.

## What the dashboard shows

Over the monitoring period, the lab generated thousands of events and alerts. The dashboard surfaces:

- Total events processed
- High-level alert counts and severity distribution
- Authentication successes/failures
- Alert evolution over time
- MITRE ATT&CK-tagged activity
- Registered agents and their status
- Alert distribution across rule categories

## What the dashboard is — and isn't — evidence of

| Question | Answered by |
|---|---|
| *What is happening across the environment?* | Dashboard |
| *What exactly happened (a specific event)?* | Event/discover view |
| *What does it mean?* | Investigation |

The dashboard is not used in this project as proof of any single incident — it's the operational overview layer, and every specific finding in ThreatLens is backed by drilling into the raw event view and building a proper investigation (see [`investigations/`](../investigations/)), not by the dashboard's summary numbers alone.

## Evidence

- `evidence/final-security-overview.png` — the Threat Hunting Dashboard view (`manager.name: ubuntu-server`, last 1 week), showing:
  - **4,823** total events, **204** Level 12+ alerts, **31** authentication failures, **203** authentication successes
  - Top 10 Alert Level Evolution over time (stacked area chart by severity level)
  - Top 10 MITRE ATT&CK techniques observed (donut chart — Modify Registry, PowerShell, Account Discovery, and others)
  - Top 5 agents by alert volume (`IMTHIAZ-WIN11` vs `ubuntu-server`)
