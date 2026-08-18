# IR-001 — Evidence

## Evidence 1: PowerShell Process Creation

**File:** `evidence/powershell-event-details.png`

**What it shows:** Sysmon Event ID 1 (Process Creation) for the encoded PowerShell execution.

**Key fields:**

```
Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine:    powershell.exe -EncodedCommand ...
User:           TPCX1\Imthiaz
IntegrityLevel: High
ParentImage:    powershell.exe
ProcessId:      23924
```

**Interpretation:** Confirms a PowerShell process launched with an encoded command, running under a standard user account at High integrity, spawned from a parent PowerShell process. This is the primary event that triggered Wazuh Rule `92057`.

**Question it answers:** *What command was executed, by whom, and through which process?*

---

## Evidence 2: Correlated File Creation

**File:** `evidence/correlated-file-creation.png`

**What it shows:** Sysmon Event ID 11 (File Creation), attributed to the same `powershell.exe` process, occurring one second after the encoded execution.

**Key fields:**

```
Image:          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\Imthiaz\AppData\Local\Temp\__PSScriptPolicyTest_....ps1
```

**Interpretation:** The `__PSScriptPolicyTest_*.ps1` naming pattern is a known artifact of PowerShell's own script-execution-policy validation mechanism — it is not, by itself, evidence of malicious tooling. Its significance here is methodological: it demonstrates that the investigation didn't stop at the initial alert, but pivoted to related telemetry (same process image, adjacent timestamp) to build a fuller picture of what the process actually did.

**Question it answers:** *What activity occurred immediately around the PowerShell execution?*

---

## Chain of custody / evidence sources

All evidence in this case originates from Sysmon telemetry forwarded through the Wazuh Agent to the Wazuh Manager, viewed via the Wazuh Dashboard event/discover interface on the Ubuntu server. No external tooling was used to modify or reprocess the raw events shown.
