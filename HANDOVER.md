# AD Audit Toolkit — Handover Document

**Version:** 1.0.0
**Author:** Shashankt255
**Date:** 2026-11-13
**Location:** `/home/kali/ad-audit-toolkit/`

---

## Purpose

Portable Active Directory security assessment toolkit for authorized penetration testing engagements. Designed for deployment on Windows client laptops. Performs read-only enumeration and passive vulnerability detection — zero exploitation, zero password guessing, zero account lockout risk.

Built from experience on TANDON.LOCAL (Infinx Red Team, 215+ findings across 12 sessions) and Perfios Switch grey box (strict stealth/SOC constraints).

---

## Architecture

```
ad-audit-toolkit/
├── ad_audit.py              # Main orchestrator — CLI, LDAP connect, module runner
├── config.py                # Constants, severity/status enums, MITRE mapping, risk weights
├── requirements.txt         # Python dependencies (ldap3, impacket, dnspython, rich, jinja2)
├── run.bat                  # Windows launcher (auto-installs deps)
├── run.sh                   # Linux launcher
├── modules/
│   ├── base.py              # BaseModule class + Finding dataclass (13 fields incl. mitre_technique)
│   ├── domain_recon.py      # DOM-001→006: Domain info, DCs, trusts, functional levels, sites
│   ├── user_audit.py        # USR-001→012: Users, privileges, password flags, Kerberoast, AS-REP
│   ├── group_audit.py       # GRP-001→007: Nesting, operators, managers, Protected Users coverage
│   ├── computer_audit.py    # CMP-001→006: Unsupported OS, delegation, stale, LAPS, MAQ
│   ├── password_audit.py    # PWD-001→004: Domain policy, FGPPs, lockout, password age
│   ├── kerberos_audit.py    # KRB-001→006: Kerberoasting, AS-REP, weak enc, krbtgt age, AES
│   ├── acl_audit.py         # ACL-001→004: DCSync rights (impacket SD parsing), AdminCount, Shadow Creds
│   ├── adcs_audit.py        # ADCS-001→008: CA enum, ESC1-ESC4, ESC6, ESC8, ESC11
│   ├── smb_audit.py         # SMB-001→004: Signing, SMBv1, null sessions, share enum
│   ├── ldap_audit.py        # LDAP-001→005: Signing, channel binding, anonymous bind, LDAPS
│   ├── delegation_audit.py  # DEL-001→006: Unconstrained, constrained, RBCD, T2A4D, priv targets
│   ├── gpo_audit.py         # GPO-001→004: Enumeration, permissions, GPP passwords, WSUS HTTP
│   ├── dns_audit.py         # DNS-001→003: Zone transfer, ADIDNS wildcard, dynamic updates
│   ├── cve_audit.py         # CVE-001→009: ZeroLogon, PetitPotam, PrintNightmare, noPac, Certifried,
│   │                        #   NTLM Relay Combined, DFSCoerce, ShadowCoerce, KrbRelayUp
│   └── misc_audit.py        # MISC-001→009: LAPS, MAQ, functional level, Recycle Bin, SID History,
│                             #   Exchange integration, GMSA, Azure AD Connect, Tombstone
└── reporting/
    └── html_report.py       # HTML report (dark theme, risk score A-F, MITRE ATT&CK, attack paths,
                              #   top 5 risks, module timing) + JSON/CSV export functions
```

---

## Stats

- **6,115 lines** of Python across 21 files
- **93 unique test cases** across 15 modules
- **24 MITRE ATT&CK** technique mappings
- **7 attack path** chains visualized in report
- **3 output formats:** HTML, JSON, CSV

---

## Safety Constraints (Hardcoded)

- **Zero password attempts** — all checks use authenticated LDAP read queries only
- **Zero LDAP writes** — no modifications to any AD objects
- **Zero exploitation** — CVE checks are version/indicator-based, RPC checks are bind-only (no payloads)
- **Zero account lockout risk** — no auth attempts against enumerated accounts
- **Zero DoS vectors** — no floods, timeouts on all network calls
- **Stealth mode available** (`--stealth`) — random 1-3s jitter between modules for SOC environments

---

## Usage

### Basic
```bash
python ad_audit.py -d corp.local -u auditor -p 'password' -dc 10.0.0.1
```

### LDAPS
```bash
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 --use-ldaps
```

### Kerberos Auth (requires kinit TGT)
```bash
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 -k
```

### Pass-the-Hash
```bash
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 --hashes LM:NT
```

### Stealth Mode (SOC-safe)
```bash
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 --stealth
```

### Selective Modules
```bash
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 -m kerberos,acl,adcs,cve
```

### Custom Output
```bash
python ad_audit.py -d corp.local -u auditor -dc 10.0.0.1 -o client_report.html --json-output client.json --csv-output client.csv
```

### Windows
```
run.bat    # Interactive — auto-installs deps, prompts for domain/user/DC
```

---

## Output Formats

1. **HTML Report** (default: `ad_audit_report.html`)
   - Dark professional theme, print-friendly
   - Executive Summary with Risk Score (A-F, 0-100) and Top 5 Critical Risks
   - Severity Distribution chart (CSS bars)
   - Test Case Matrix (93 rows) with MITRE ATT&CK links
   - Risk Summary grouped by CRITICAL/HIGH/MEDIUM/LOW
   - Attack Path Visualization (7 chains)
   - Detailed Finding Cards with description, observation, affected objects, remediation, CVE, references
   - Module Execution Timing in Appendix

2. **JSON** (`--json-output` or auto-generated alongside HTML)
   - Machine-readable for toolchain integration (BloodHound, SIEM, ticketing)

3. **CSV** (`--csv-output` or auto-generated alongside HTML)
   - Spreadsheet-friendly for client handoff and tracking

---

## Dependencies

```
ldap3>=2.9.1          # LDAP queries (pure Python, cross-platform)
impacket>=0.12.0      # SMB, RPC endpoint probing, SD parsing
dnspython>=2.6.0      # DNS zone transfer, record queries
rich>=13.7.0          # Console output (progress, tables, panels)
jinja2>=3.1.3         # HTML report templating
cryptography>=42.0.0  # TLS/crypto support
pyasn1>=0.6.0         # ASN.1 parsing for Kerberos/LDAP
```

---

## Test Case Summary by Severity Target

### CRITICAL findings detected:
- DCSync rights on non-default principals (ACL-001)
- Unconstrained delegation on non-DC computers (DEL-001, CMP-005)
- AD CS ESC1 vulnerable templates (ADCS-003)
- SID History with privileged SIDs (MISC-005)
- Exchange Windows Permissions DCSync path (MISC-006)
- ZeroLogon / PrintNightmare indicators (CVE-001, CVE-003)
- NTLM Relay combined chain viable (CVE-006)

### HIGH findings detected:
- Kerberoastable accounts (KRB-001, USR-009)
- AS-REP roastable accounts (KRB-002, USR-005)
- SMB signing not required (SMB-001)
- Constrained delegation with protocol transition (DEL-004)
- LAPS not deployed (MISC-001)
- MachineAccountQuota > 0 (MISC-002)
- Azure AD Connect sync accounts (MISC-008)
- KrbRelayUp viable (CVE-009)

---

## Known Limitations

- ACL-001 DCSync detection depends on impacket SD parsing; falls back to heuristic (adminCount + group membership) if parsing fails
- CVE checks (CVE-001→003) are indicator-based, not exploit-based — they WARN by default and recommend manual patch verification
- GPP password check (GPO-003) cannot access SYSVOL via LDAP — flags INFO for manual review
- RPC endpoint checks (CVE-007/008 DFSCoerce/ShadowCoerce) require network access to DC RPC ports
- No SCCM/MECM checks (requires WMI, not LDAP-accessible)
- No tiering model violation detection (requires logon event analysis)

---

## Build Process

This toolkit was built in a single session using 11 parallel agents:
1. 4 agents wrote the initial 15 modules + report generator + main script
2. 1 agent audited code quality (found 6 critical class name mismatches, fixed)
3. 1 agent reviewed for missing features (identified 6 P0, 11 P1, 10 P2)
4. 3 agents implemented P0s + key P1s in parallel
5. Final integration dry run: 19/19 files pass syntax, all 15 modules import clean

---

## Next Steps / Future Enhancements

- [ ] PyInstaller packaging for standalone .exe (no Python needed on client)
- [ ] BloodHound JSON ingest format export
- [ ] Report comparison/diff mode (track remediation progress)
- [ ] SOCKS proxy support for pivoted access
- [ ] Resume/checkpoint for large environments with timeouts
- [ ] Compliance mapping (CIS Benchmarks, NIST 800-53)
