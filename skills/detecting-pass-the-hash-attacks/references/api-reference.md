# API Reference: Detecting Pass-the-Hash Attacks

## python-evtx Library
```python
from Evtx.Evtx import FileHeader
with open("Security.evtx", "rb") as f:
    fh = FileHeader(f)
    for record in fh.records():
        xml_string = record.xml()
```

## Event 4624 - NTLM Network Logon (PTH Indicator)
```xml
<Data Name="TargetUserName">admin</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="LmPackageName">NTLM V2</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="KeyLength">0</Data>
<Data Name="IpAddress">10.0.0.50</Data>
<Data Name="WorkstationName">ATTACKER-PC</Data>
```

## PTH Detection Indicators
| Field | PTH Value | Normal |
|-------|-----------|--------|
| LogonType | 3 (Network) | Various |
| AuthenticationPackageName | NTLM | Kerberos |
| LogonProcessName | NtLmSsp | Kerberos |
| KeyLength | 0 | 128 |
| LmPackageName | NTLM V1 (weaker) | NTLM V2 |

## Detection Logic
1. Filter 4624 where LogonType=3 AND AuthenticationPackageName=NTLM
2. Flag events with KeyLength=0 (hash-only authentication)
3. Detect same account authenticating from 3+ different source IPs
4. Detect account used from 3+ different workstation names
5. Correlate with process creation (4688) for post-exploitation activity

## MITRE ATT&CK
- T1550.002 - Pass the Hash
- T1078 - Valid Accounts
