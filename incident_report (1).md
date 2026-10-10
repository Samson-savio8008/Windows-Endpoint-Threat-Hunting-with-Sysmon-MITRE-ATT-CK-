# Incident Report: LSASS credential dumping via comsvcs.dll

**Source:** OTRF Security-Datasets, scenario `psh_lsass_memory_dump_comsvcs` (a controlled lab simulation, not a live incident)
**Analyst:** Samson Savio
**Detection:** rules R01 and R02 in `detect.py`

## Summary
On host WORKSTATION5, a PowerShell session run by user `wardog` launched `rundll32.exe` to call the `MiniDump` export in `comsvcs.dll`. It wrote a full memory dump of the LSASS process to a temp folder. This is a well-known technique for stealing credentials from memory, and it uses only built-in Windows tools, so it can slip past simple allow-listing.

## Timeline (UTC, 2020-10-18)
| Time | Event | Source |
|---|---|---|
| 23:50:05.910 | `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 756 C:\Users\wardog\AppData\Local\Temp\lsass-comsvcs.dmp full`, started by `powershell.exe` | Sysmon EID 1 |
| 23:50:05.963 | `rundll32.exe` creates `lsass-comsvcs.dmp` in the user's Temp folder | Sysmon EID 11 |
| 23:50:05.963 | `rundll32.exe` opens `lsass.exe` with access mask `0x1410` | Sysmon EID 10 |
| 23:50:05.994 | `rundll32.exe` opens `lsass.exe` again with access mask `0x1fffff` (full access) | Sysmon EID 10 |

The whole sequence took about 84 milliseconds.

## Why this is a true positive
- `rundll32` calling `comsvcs.dll` with `MiniDump` has almost no legitimate use.
- The target process ID (756) matches `lsass.exe`, confirmed by the Sysmon process-access events.
- A full-access mask (`0x1fffff`) on LSASS from a non-system process is a strong credential-theft indicator.
- The output file is named like an LSASS dump and written to a user-writable folder.

## ATT&CK mapping
- **T1003.001** OS Credential Dumping: LSASS Memory (tactic: Credential Access)

## Severity and confidence
- **Severity:** High. Any account logged on to this host could have had credentials exposed.
- **Confidence:** High. Three independent log events agree.

## Recommended actions
1. Isolate WORKSTATION5 and collect the dump file as evidence.
2. Treat all credentials used on the host as compromised and reset them, starting with privileged accounts.
3. Find how the PowerShell session started (parent process and user logon) to identify initial access.
4. Hardening: enable LSASS protection (RunAsPPL) and Credential Guard, and restrict who can debug processes.
5. Detection: keep rules R01 and R02, and alert on any new `.dmp` file written by `rundll32.exe`.
