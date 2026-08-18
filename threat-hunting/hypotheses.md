# Hunting Hypotheses

Each hunt in ThreatLens started from a specific, testable hypothesis rather than an unfocused search. This is what makes it threat *hunting* rather than casual browsing of the dashboard.

## Hypothesis 1 — Encoded PowerShell

**Question:** Could encoded PowerShell execution on this endpoint indicate suspicious activity?

**Approach:** Search Sysmon Event ID 1 telemetry for `powershell.exe` process creations containing `-EncodedCommand` in the command line, then examine parent process and any immediately correlated file/registry activity.

**Result:** Confirmed activity, investigated fully as [IR-001](../investigations/IR-001-encoded-powershell/README.md).

## Hypothesis 2 — Unexpected `net.exe` usage

**Question:** Could unexpected `net.exe`/`net1.exe` usage on this endpoint indicate account discovery activity?

**Approach:** Search process creation telemetry for `net1.exe` spawned by `net.exe` with command lines consistent with enumeration (`user`, `group`, `localgroup`), then review the executing user/privilege context.

**Result:** Confirmed activity, investigated fully as [IR-002](../investigations/IR-002-account-discovery/README.md).

## Hypothesis 3 — Registry Run Key modification

**Question:** Could Run Key modification on this endpoint represent a persistence mechanism?

**Approach:** Search Sysmon Event ID 13 telemetry for `SetValue` events targeting `...CurrentVersion\Run` / `RunOnce` paths, then identify the writing process and evaluate whether the referenced executable is expected.

**Result:** Confirmed activity, investigated as part of the [registry-persistence detection](../detections/registry-persistence/README.md).

## General approach going forward

These three hypotheses map directly to the three validated detections in this project — in a mature SOC workflow, a hunt that repeatedly confirms the same pattern is a strong signal that the pattern deserves a permanent, automated detection rule rather than continued manual hunting. That's exactly how Rules `100100` and `100102` came to exist as custom detections.
