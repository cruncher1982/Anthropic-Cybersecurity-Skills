# API Reference: Detecting Privilege Escalation Attempts

## Windows Security Event IDs

| Event ID | Description |
|----------|-------------|
| 4672 | Special privileges assigned to new logon |
| 4673 | A privileged service was called |
| 4674 | Operation attempted on a privileged object |
| 4688 | New process created (token elevation check) |
| 4703 | User right was adjusted |

## Sysmon Event IDs

| Event ID | Description |
|----------|-------------|
| 1 | Process Create with IntegrityLevel field |
| 10 | ProcessAccess (token duplication detection) |
| 13 | RegistryEvent (UAC bypass registry keys) |

## Key Libraries

- **pywin32** (`pip install pywin32`): `win32evtlog.OpenEventLog()`, `ReadEventLog()`, `CloseEventLog()`
- **python-evtx** (`pip install python-evtx`): Parse EVTX files offline with `Evtx.Evtx(path)`
- **re** (stdlib): Pattern matching for UAC bypass indicators in command lines

## UAC Bypass Detection Patterns

| Binary | Registry Key |
|--------|-------------|
| `fodhelper.exe` | `HKCU\Software\Classes\ms-settings\shell\open\command` |
| `eventvwr.exe` | `HKCU\Software\Classes\mscfile\shell\open\command` |
| `sdclt.exe` | `HKCU\Software\Classes\exefile\shell\runas\command` |
| `computerdefaults.exe` | `HKCU\Software\Classes\ms-settings\shell\open\command` |

## Configuration

| Variable | Description |
|----------|-------------|
| `PRIV_ESC_EVENT_IDS` | Map of Security event IDs to descriptions |
| `SUSPICIOUS_PROCESSES` | List of processes to flag when running elevated |
| `UAC_BYPASS_INDICATORS` | Regex patterns for known UAC bypass techniques |

## References

- [MITRE ATT&CK T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [MITRE ATT&CK T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
- [Windows Security Auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
