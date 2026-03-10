# API Reference: Ransomware Precursor Detection

## Zeek (Bro) conn.log Fields

### Tab-separated Fields
| Index | Field | Description |
|-------|-------|-------------|
| 0 | ts | Timestamp |
| 1 | uid | Connection UID |
| 2 | id.orig_h | Source IP |
| 3 | id.orig_p | Source port |
| 4 | id.resp_h | Destination IP |
| 5 | id.resp_p | Destination port |
| 6 | proto | Protocol (tcp/udp) |
| 7 | service | Detected service |
| 8 | duration | Connection duration |
| 9 | orig_bytes | Bytes from originator |
| 10 | resp_bytes | Bytes from responder |

## Ransomware-Associated Network Indicators

### Ports
| Port | Service | Risk |
|------|---------|------|
| 445 | SMB | Lateral movement, EternalBlue |
| 3389 | RDP | Brute force, initial access |
| 4444 | Metasploit default | C2 callback |
| 135 | RPC | WMI lateral movement |
| 5985/5986 | WinRM | Remote execution |

## Windows Event Log IDs

### Security Log
| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon (brute force indicator) |
| 4624 | Successful logon (type 3 = network) |
| 4648 | Explicit credential logon |
| 4672 | Special privileges assigned |

### System Log
| Event ID | Description |
|----------|-------------|
| 7036 | Service state change (VSS) |
| 7045 | New service installed |

### PowerShell Operational Log
| Event ID | Description |
|----------|-------------|
| 4104 | Script block logging |
| 4103 | Module logging |

## Shadow Copy Deletion Commands
```
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled no
bcdedit /set {default} bootstatuspolicy ignoreallfailures
wbadmin delete catalog -quiet
```

## Suricata Rules for Ransomware Detection
```
alert smb any any -> $HOME_NET 445 (msg:"ET EXPLOIT EternalBlue";
  content:"|ff|SMB|73|"; sid:2024217; rev:3;)

alert tcp $HOME_NET any -> any 443 (msg:"Ransomware C2 beacon";
  flow:established,to_server; content:"POST";
  pcre:"/\/[a-z]{4,8}\/[a-f0-9]{32}/i"; sid:9000001;)
```

## CrowdStrike Falcon API — IOC Search
```http
GET https://api.crowdstrike.com/indicators/queries/iocs/v1
Authorization: Bearer {token}
Content-Type: application/json

?types=domain&values=malicious-domain.com
```

### Response
```json
{
  "resources": ["indicator_id_1"],
  "meta": {"query_time": 0.005}
}
```
