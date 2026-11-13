# AD Audit Toolkit

Portable Active Directory security assessment toolkit for authorized penetration testing. Runs **93 automated test cases** across 15 modules, generates professional reports with risk scoring, MITRE ATT&CK mapping, and attack path visualization.

Designed for deployment on client Windows laptops. 100% read-only — zero exploitation, zero password guessing, zero account lockout risk.

```
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1
```

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## Features

### 93 Test Cases Across 15 Modules

| Module | Tests | What It Checks |
|--------|:-----:|----------------|
| **Domain Recon** | DOM-001→006 | Domain info, DCs, trust relationships, functional levels, sites & subnets |
| **User Audit** | USR-001→012 | Privileged users, Kerberoastable SPNs, AS-REP roastable, stale accounts, password flags, reversible encryption |
| **Group Audit** | GRP-001→007 | Nested privileged groups, operator group membership, Protected Users coverage |
| **Computer Audit** | CMP-001→006 | Unsupported OS (Win7/2008/2012), unconstrained delegation, LAPS coverage, MachineAccountQuota |
| **Password Policy** | PWD-001→004 | Domain password policy, fine-grained policies, lockout settings, password age |
| **Kerberos** | KRB-001→006 | Kerberoasting, AS-REP roasting, weak encryption types, krbtgt password age, AES key status |
| **ACL Audit** | ACL-001→004 | DCSync rights, orphaned AdminCount, AdminSDHolder, Shadow Credentials |
| **AD CS** | ADCS-001→008 | Certificate Authority enum, ESC1–ESC4, ESC6, ESC8, ESC11 template misconfigurations |
| **SMB** | SMB-001→004 | Signing enforcement, SMBv1, null sessions, share enumeration |
| **LDAP** | LDAP-001→005 | Signing enforcement, channel binding, anonymous bind, LDAPS availability |
| **Delegation** | DEL-001→006 | Unconstrained, constrained, RBCD, protocol transition (T2A4D), privileged service targets |
| **GPO** | GPO-001→004 | GPO enumeration, GPP passwords (cpassword), WSUS HTTP poisoning |
| **DNS** | DNS-001→003 | Zone transfer, ADIDNS wildcard records, insecure dynamic updates |
| **CVE Detection** | CVE-001→009 | ZeroLogon, PetitPotam, PrintNightmare, noPac, Certifried, NTLM Relay chain, DFSCoerce, ShadowCoerce, KrbRelayUp |
| **Miscellaneous** | MISC-001→009 | LAPS deployment, MachineAccountQuota, AD Recycle Bin, SID History abuse, Exchange WriteDACL path, gMSA, Azure AD Connect, Tombstone lifetime |

### Reporting

- **HTML Report** — Dark-themed, professional, print-ready
  - Executive Summary with **Risk Score (A–F, 0–100)**
  - **Top 5 Critical Risks** at a glance
  - Severity distribution chart
  - Full test case matrix with **MITRE ATT&CK** technique links (24 mappings)
  - **Attack Path Visualization** — 7 attack chains (e.g., PetitPotam → Relay → DCSync)
  - Detailed finding cards with observations, affected objects, remediation, CVE references
  - Module execution timing breakdown
- **JSON Export** — Machine-readable for SIEM/ticketing integration
- **CSV Export** — Spreadsheet-friendly for client handoff

### Operational Features

- **Stealth Mode** (`--stealth`) — Random jitter between modules for SOC-monitored environments
- **Kerberos Auth** (`-k`) — GSSAPI authentication via kinit TGT
- **Pass-the-Hash** (`--hashes`) — NTLM hash authentication
- **LDAPS** (`--use-ldaps`) — Encrypted LDAP over port 636
- **Selective Modules** (`-m`) — Run only the modules you need

---

## Quick Start

### Windows

```
# Double-click run.bat — auto-installs dependencies, prompts for connection details
run.bat
```

### Linux / macOS

```bash
pip install -r requirements.txt
python3 ad_audit.py -d corp.local -u auditor -dc 10.0.0.1
```

### Docker (Optional)

```bash
docker run -v $(pwd)/reports:/reports ad-audit-toolkit -d corp.local -u auditor -dc 10.0.0.1 -o /reports/output.html
```

---

## Usage

```
usage: ad_audit.py [-h] -d DOMAIN -u USERNAME [-p PASSWORD] -dc DC_IP
                   [--use-ldaps] [--port PORT] [-o OUTPUT] [-m MODULES]
                   [--timeout TIMEOUT] [-v] [--hashes HASHES] [-k]
                   [--stealth] [--json-output PATH] [--csv-output PATH]
                   [--list-modules]
```

### Examples

```bash
# Basic scan — all modules, HTML report
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1

# LDAPS with custom output
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 --use-ldaps -o client_report.html

# Kerberos authentication (requires valid TGT via kinit)
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 -k

# Pass-the-Hash
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 --hashes aad3b435b51404eeaad3b435b51404ee:ntlmhash

# Stealth mode for SOC-monitored environments
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 --stealth

# Run specific modules only
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 -m kerberos,acl,adcs,cve

# All export formats
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 -o report.html --json-output report.json --csv-output report.csv

# List available modules
python ad_audit.py --list-modules
```

---

## Installation

### Requirements

- Python 3.8+
- Network access to target Domain Controller (LDAP/389, LDAPS/636, SMB/445, RPC/135)
- Valid domain credentials (user-level is sufficient for most checks)

### Install Dependencies

```bash
pip install -r requirements.txt
```

| Package | Purpose |
|---------|---------|
| `ldap3` | LDAP queries (pure Python, cross-platform) |
| `impacket` | SMB negotiation, RPC endpoint probing, Security Descriptor parsing |
| `dnspython` | DNS zone transfer and record queries |
| `rich` | Console output — progress display, tables, panels |
| `jinja2` | HTML report templating |
| `cryptography` | TLS/crypto support |
| `pyasn1` | ASN.1 parsing for Kerberos/LDAP structures |

---

## Report Samples

### Executive Summary
The report opens with a risk score (A–F grade) and severity distribution:

```
Risk Score: D (38/100)
CRITICAL: 4  |  HIGH: 11  |  MEDIUM: 8  |  LOW: 3
```

### Attack Paths
Detected attack chains are visualized:

```
[PetitPotam Coerce] → [NTLM Relay (SMB signing off)] → [DCSync] → Domain Compromise
[Kerberoastable DA] → [Offline Hash Crack] → Domain Admin Access
[MAQ > 0 + LDAP Signing Off] → [KrbRelayUp / RBCD] → Privilege Escalation
```

### Test Case Matrix

| Test ID | Test Name | Status | Severity | MITRE |
|---------|-----------|--------|----------|-------|
| KRB-001 | Kerberoastable Accounts | FAIL | HIGH | T1558.003 |
| ACL-001 | DCSync Rights | PASS | INFO | T1003.006 |
| CVE-006 | NTLM Relay Combined | FAIL | CRITICAL | T1557.001 |

---

## Safety Guarantees

This toolkit is designed for **authorized security assessments only**. Every check is passive and non-destructive:

| Constraint | Implementation |
|-----------|----------------|
| **No password guessing** | Uses only the provided credentials — zero authentication attempts against enumerated accounts |
| **No LDAP writes** | All queries are search/read operations — no modifications to any AD objects |
| **No exploitation** | CVE checks use version fingerprinting and indicator detection — no exploit payloads sent |
| **No account lockout** | Zero wrong-password attempts — impossible to trigger lockout policies |
| **No DoS** | No resource exhaustion — standard LDAP pagination, timeouts on all network calls |
| **RPC checks** | Bind-only to check endpoint availability — no exploit or coerce payloads |
| **Stealth mode** | Optional random delays between modules to minimize detection footprint |

---

## Architecture

```
ad-audit-toolkit/
├── ad_audit.py              # CLI orchestrator — args, LDAP connect, module pipeline, exports
├── config.py                # Constants, MITRE ATT&CK mapping (24), risk weights
├── requirements.txt         # Python dependencies
├── run.bat / run.sh         # OS-specific launchers
│
├── modules/
│   ├── base.py              # BaseModule class + Finding dataclass (13 fields)
│   ├── domain_recon.py      # DOM-001 → DOM-006
│   ├── user_audit.py        # USR-001 → USR-012
│   ├── group_audit.py       # GRP-001 → GRP-007
│   ├── computer_audit.py    # CMP-001 → CMP-006
│   ├── password_audit.py    # PWD-001 → PWD-004
│   ├── kerberos_audit.py    # KRB-001 → KRB-006
│   ├── acl_audit.py         # ACL-001 → ACL-004
│   ├── adcs_audit.py        # ADCS-001 → ADCS-008
│   ├── smb_audit.py         # SMB-001 → SMB-004
│   ├── ldap_audit.py        # LDAP-001 → LDAP-005
│   ├── delegation_audit.py  # DEL-001 → DEL-006
│   ├── gpo_audit.py         # GPO-001 → GPO-004
│   ├── dns_audit.py         # DNS-001 → DNS-003
│   ├── cve_audit.py         # CVE-001 → CVE-009
│   └── misc_audit.py        # MISC-001 → MISC-009
│
└── reporting/
    └── html_report.py       # HTML report + generate_json_report() + generate_csv_report()
```

### How It Works

1. **Connect** — Authenticates to the target DC via LDAP (NTLM, Kerberos, or PtH)
2. **Discover** — Pulls domain DN, configuration DN, schema DN, DC list from RootDSE
3. **Audit** — Runs each module sequentially (with optional stealth jitter), collecting Finding objects
4. **Report** — Generates HTML report with risk score, MITRE mapping, attack paths, and detailed findings
5. **Export** — Optionally exports JSON and CSV alongside HTML

### Writing Custom Modules

```python
from modules.base import BaseModule
from config import *

class MyCustomAudit(BaseModule):
    MODULE_NAME = "Custom Audit"
    MODULE_DESCRIPTION = "Description of what this checks"

    def execute(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=user)",
            attributes=["sAMAccountName"],
        )
        self.add_finding(
            test_id="CUSTOM-001",
            test_name="My Custom Check",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if entries else STATUS_PASS,
            severity=SEVERITY_HIGH,
            description="What this check does.",
            observation=f"Found {len(entries)} objects.",
            remediation="How to fix it.",
        )
```

Register it in `AVAILABLE_MODULES` in `ad_audit.py` and it's ready to run.

---

## MITRE ATT&CK Coverage

| Technique | ID | Test Cases |
|-----------|----|------------|
| Kerberoasting | T1558.003 | KRB-001, USR-009 |
| AS-REP Roasting | T1558.004 | KRB-002, USR-005 |
| DCSync | T1003.006 | ACL-001 |
| Forced Authentication | T1187 | CVE-002 |
| LLMNR/NBT-NS Poisoning & SMB Relay | T1557.001 | SMB-001 |
| Steal/Forge Authentication Certificates | T1649 | ADCS-003→008, CVE-005 |
| Unsecured Credentials: GPP | T1552.006 | GPO-003 |
| Exploitation of Remote Services | T1210 | CVE-001, CVE-003 |
| SID History Injection | T1134.005 | MISC-005 |
| Valid Accounts | T1078 | CVE-004 |
| Pass the Ticket | T1550.003 | DEL-001, DEL-002, DEL-004 |
| Token Manipulation | T1134 | CMP-005 |

---

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Use it only on systems you have explicit written permission to test. Unauthorized access to computer systems is illegal. The author is not responsible for any misuse or damage caused by this tool.

Always obtain proper authorization before running any security assessment.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**[Shashankt255](https://github.com/Shashankt255)**
