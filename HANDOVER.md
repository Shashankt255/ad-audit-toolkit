# AD Audit Toolkit — Handover

## Status: COMPLETE (v1.0.0)

## Overview
Python-based Active Directory security assessment toolkit. Safe, read-only, non-destructive — zero DoS risk, zero account lockout, zero brute force. Designed to run on client Windows laptops or any Python 3.8+ environment.

## Architecture
- **ad_audit.py** — Main CLI orchestrator (argparse, LDAP connection, module pipeline, report generation)
- **config.py** — Constants (severity levels, privileged groups, GUIDs, thresholds)
- **modules/base.py** — BaseModule class + Finding dataclass (all modules extend this)
- **reporting/html_report.py** — Jinja2 HTML report with dark theme, severity charts, test matrix, finding cards
- **run.bat** — Windows launcher (auto-installs deps, runs tool)
- **run.sh** — Linux/macOS launcher

## Modules (15 total, ~60+ test cases)

| Module | File | Key Checks |
|--------|------|------------|
| Domain Recon | domain_recon.py | Domain info, DCs, trusts, sites, functional level |
| User Audit | user_audit.py | Privileged users, stale accounts, password flags, adminCount, reversible encryption |
| Group Audit | group_audit.py | Nested memberships, empty privileged groups, privilege sprawl |
| Computer Audit | computer_audit.py | Unsupported OS, stale computers, LAPS deployment, DC inventory |
| Kerberos Audit | kerberos_audit.py | Kerberoastable SPNs, AS-REP roastable, weak encryption, pre-auth |
| Password Policy | password_audit.py | Domain policy, fine-grained policies, lockout settings |
| ACL Audit | acl_audit.py | DCSync rights, AdminSDHolder ACL, domain object permissions |
| AD CS Audit | adcs_audit.py | CA enrollment, ESC1-ESC8 template vulnerabilities |
| SMB Audit | smb_audit.py | Signing, null sessions, SMBv1 detection |
| LDAP Audit | ldap_audit.py | Signing, channel binding, anonymous bind |
| Delegation Audit | delegation_audit.py | Unconstrained, constrained, RBCD, protocol transition, privileged targets |
| GPO Audit | gpo_audit.py | GPO inventory, Default Domain Policy, enforced links |
| DNS Audit | dns_audit.py | Zone transfer, dynamic updates, zone inventory |
| CVE Audit | cve_audit.py | ZeroLogon, PetitPotam, PrintNightmare, noPac, Certifried, KrbRelayUp |
| Miscellaneous | misc_audit.py | Tombstone lifetime, Recycle Bin, Protected Users, KRBTGT age, MAQ, schema version |

## Usage
```bash
# Windows (interactive — prompts for all params, auto-installs deps)
run.bat

# Linux/macOS
pip install -r requirements.txt
python3 ad_audit.py -d corp.local -u admin -p 'P@ss' -dc 10.0.0.1

# LDAPS
python3 ad_audit.py -d corp.local -u admin -dc 10.0.0.1 --use-ldaps

# Pass-the-hash
python3 ad_audit.py -d corp.local -u admin -dc 10.0.0.1 --hashes LM:NT

# Specific modules only
python3 ad_audit.py -d corp.local -u admin -dc 10.0.0.1 -m kerberos,acl,adcs,cve

# List modules
python3 ad_audit.py --list-modules
```

## Report Output
- HTML file with dark theme, executive summary, severity distribution chart
- Test case matrix (all checks with PASS/FAIL/WARN/INFO status)
- Risk summary grouped by severity
- Detailed finding cards with description, observation, affected objects, remediation, CVE references

## Safety Guarantees
- **Read-only LDAP queries only** — no writes, no modifications
- **No authentication attempts** — uses provided credentials only, never brute-forces
- **No exploit payloads** — CVE checks use passive indicators (OS version, attribute presence, configuration values)
- **No DoS** — no flooding, no resource exhaustion, all queries use standard LDAP pagination
- **SMB checks** — bind-only negotiation, no file operations

## Dependencies
ldap3, impacket, dnspython, rich, jinja2, cryptography, pyasn1

## Files
```
ad-audit-toolkit/
├── ad_audit.py          # Main orchestrator (313 lines)
├── config.py            # Configuration constants
├── requirements.txt     # Python dependencies
├── run.bat              # Windows launcher
├── run.sh               # Linux launcher
├── modules/
│   ├── base.py          # BaseModule + Finding dataclass
│   ├── domain_recon.py  # Domain enumeration
│   ├── user_audit.py    # User security audit
│   ├── group_audit.py   # Group security audit
│   ├── computer_audit.py # Computer audit
│   ├── kerberos_audit.py # Kerberos checks
│   ├── password_audit.py # Password policy audit
│   ├── acl_audit.py     # ACL analysis
│   ├── adcs_audit.py    # AD Certificate Services
│   ├── smb_audit.py     # SMB security
│   ├── ldap_audit.py    # LDAP security
│   ├── delegation_audit.py # Delegation abuse
│   ├── gpo_audit.py     # GPO security
│   ├── dns_audit.py     # DNS security
│   ├── cve_audit.py     # CVE detection
│   └── misc_audit.py    # Miscellaneous checks
└── reporting/
    └── html_report.py   # HTML report generator
```
