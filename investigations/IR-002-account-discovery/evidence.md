# IR-002 — Evidence

## Evidence 1: Account Discovery Process Creation

**File:** `evidence/account-discovery-event.png`

**What it shows:** Sysmon Event ID 1 (Process Creation) for the `net1.exe user` execution that triggered custom Rule `100100`.

**Key fields:**

```
CommandLine:    C:\WINDOWS\System32\net1 user
Image:          C:\Windows\SysWOW64\net1.exe
ParentImage:    C:\Windows\SysWOW64\net.exe
IntegrityLevel: System
User:           NT AUTHORITY\SYSTEM
```

**Interpretation:** Confirms exactly which binary executed, its parent process, the command issued, and the privilege context (`SYSTEM`). This is the complete picture needed to assess the discovery activity without relying on the alert description alone.

**Question it answers:** *What exactly did `net.exe` execute?*
