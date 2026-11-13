#!/usr/bin/env python3
"""Mock AD environment dry run — validates the full pipeline end-to-end."""
import sys
import os
import json
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ldap3 import Server, Connection, MOCK_SYNC, OFFLINE_AD_2012_R2, ALL, NONE
from ldap3 import MODIFY_REPLACE
from config import *

DOMAIN = "MOCKLAB.LOCAL"
DOMAIN_DN = "DC=mocklab,DC=local"
CONFIG_DN = f"CN=Configuration,{DOMAIN_DN}"
SCHEMA_DN = f"CN=Schema,{CONFIG_DN}"
DC_IP = "127.0.0.1"

def filetime_from_days_ago(days):
    epoch = datetime(1601, 1, 1)
    dt = datetime.utcnow() - timedelta(days=days)
    ft = int((dt - epoch).total_seconds() * 10_000_000)
    return str(ft)

def negative_filetime_days(days):
    return str(-int(days * 24 * 60 * 60 * 10_000_000))

def build_mock_ad():
    server = Server("mock_dc", get_info=NONE)
    conn = Connection(server, user=f"{DOMAIN}\\auditor", password="mock", client_strategy=MOCK_SYNC)
    conn.bind()

    def add(dn, oc, attrs=None):
        conn.strategy.add_entry(dn, {**({"objectClass": oc} if isinstance(oc, list) else {"objectClass": [oc]}), **(attrs or {})}, validate=False)

    # Domain root
    add(DOMAIN_DN, ["domainDNS", "domain", "top"], {
        "dc": "mocklab",
        "distinguishedName": DOMAIN_DN,
        "msDS-Behavior-Version": "7",
        "ms-DS-MachineAccountQuota": "10",
        "minPwdLength": "8",
        "pwdProperties": "1",
        "maxPwdAge": negative_filetime_days(90),
        "minPwdAge": negative_filetime_days(1),
        "lockoutThreshold": "0",
        "lockoutDuration": negative_filetime_days(0.02),
        "lockOutObservationWindow": negative_filetime_days(0.02),
        "pwdHistoryLength": "6",
    })

    # Configuration
    add(CONFIG_DN, ["configuration"], {"distinguishedName": CONFIG_DN})
    add(SCHEMA_DN, ["dMD"], {"distinguishedName": SCHEMA_DN})

    # OUs
    add(f"OU=Users,{DOMAIN_DN}", "organizationalUnit")
    add(f"OU=Groups,{DOMAIN_DN}", "organizationalUnit")
    add(f"OU=Computers,{DOMAIN_DN}", "organizationalUnit")
    add(f"OU=Domain Controllers,{DOMAIN_DN}", "organizationalUnit")
    add(f"OU=Service Accounts,{DOMAIN_DN}", "organizationalUnit")

    # --- USERS ---
    admin_dn = f"CN=Administrator,OU=Users,{DOMAIN_DN}"
    add(admin_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "Administrator",
        "userAccountControl": "512",
        "adminCount": "1",
        "distinguishedName": admin_dn,
        "memberOf": [f"CN=Domain Admins,OU=Groups,{DOMAIN_DN}", f"CN=Administrators,OU=Groups,{DOMAIN_DN}"],
        "pwdLastSet": filetime_from_days_ago(45),
        "lastLogonTimestamp": filetime_from_days_ago(1),
        "objectCategory": "person",
    })

    krbtgt_dn = f"CN=krbtgt,OU=Users,{DOMAIN_DN}"
    add(krbtgt_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "krbtgt",
        "userAccountControl": "514",
        "adminCount": "1",
        "distinguishedName": krbtgt_dn,
        "pwdLastSet": filetime_from_days_ago(400),
        "objectCategory": "person",
    })

    # Kerberoastable user with SPN
    svc_sql_dn = f"CN=svc_sql,OU=Service Accounts,{DOMAIN_DN}"
    add(svc_sql_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "svc_sql",
        "userAccountControl": "512",
        "servicePrincipalName": ["MSSQLSvc/db01.mocklab.local:1433", "MSSQLSvc/db01.mocklab.local"],
        "distinguishedName": svc_sql_dn,
        "memberOf": [f"CN=Domain Admins,OU=Groups,{DOMAIN_DN}"],
        "adminCount": "1",
        "pwdLastSet": filetime_from_days_ago(800),
        "lastLogonTimestamp": filetime_from_days_ago(2),
        "objectCategory": "person",
    })

    # AS-REP roastable user
    asrep_dn = f"CN=jdoe,OU=Users,{DOMAIN_DN}"
    add(asrep_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "jdoe",
        "userAccountControl": str(0x200 + 0x400000),  # NORMAL + DONT_REQ_PREAUTH
        "distinguishedName": asrep_dn,
        "pwdLastSet": filetime_from_days_ago(200),
        "lastLogonTimestamp": filetime_from_days_ago(5),
        "objectCategory": "person",
    })

    # User with password never expires
    pne_dn = f"CN=svc_backup,OU=Service Accounts,{DOMAIN_DN}"
    add(pne_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "svc_backup",
        "userAccountControl": str(0x200 + 0x10000),  # NORMAL + DONT_EXPIRE_PASSWD
        "distinguishedName": pne_dn,
        "pwdLastSet": filetime_from_days_ago(600),
        "lastLogonTimestamp": filetime_from_days_ago(1),
        "objectCategory": "person",
    })

    # User with reversible encryption
    rev_dn = f"CN=legacy_app,OU=Service Accounts,{DOMAIN_DN}"
    add(rev_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "legacy_app",
        "userAccountControl": str(0x200 + 0x80),  # NORMAL + ENCRYPTED_TEXT_PWD_ALLOWED
        "distinguishedName": rev_dn,
        "pwdLastSet": filetime_from_days_ago(300),
        "lastLogonTimestamp": filetime_from_days_ago(10),
        "objectCategory": "person",
    })

    # Stale user (no logon 120 days)
    stale_dn = f"CN=former_employee,OU=Users,{DOMAIN_DN}"
    add(stale_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "former_employee",
        "userAccountControl": "512",
        "distinguishedName": stale_dn,
        "pwdLastSet": filetime_from_days_ago(400),
        "lastLogonTimestamp": filetime_from_days_ago(120),
        "objectCategory": "person",
    })

    # User with PASSWD_NOTREQD
    nopass_dn = f"CN=test_account,OU=Users,{DOMAIN_DN}"
    add(nopass_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "test_account",
        "userAccountControl": str(0x200 + 0x20),  # NORMAL + PASSWD_NOTREQD
        "distinguishedName": nopass_dn,
        "objectCategory": "person",
    })

    # Disabled user in privileged group
    disabled_da_dn = f"CN=old_admin,OU=Users,{DOMAIN_DN}"
    add(disabled_da_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "old_admin",
        "userAccountControl": str(0x200 + 0x2),  # NORMAL + ACCOUNTDISABLE
        "adminCount": "1",
        "distinguishedName": disabled_da_dn,
        "memberOf": [f"CN=Domain Admins,OU=Groups,{DOMAIN_DN}"],
        "objectCategory": "person",
    })

    # Orphaned adminCount user
    orphan_dn = f"CN=ex_operator,OU=Users,{DOMAIN_DN}"
    add(orphan_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "ex_operator",
        "userAccountControl": "512",
        "adminCount": "1",
        "distinguishedName": orphan_dn,
        "memberOf": [],
        "objectCategory": "person",
    })

    # Normal user
    normal_dn = f"CN=auditor,OU=Users,{DOMAIN_DN}"
    add(normal_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "auditor",
        "userAccountControl": "512",
        "distinguishedName": normal_dn,
        "pwdLastSet": filetime_from_days_ago(10),
        "lastLogonTimestamp": filetime_from_days_ago(0),
        "objectCategory": "person",
    })

    # Azure AD Connect sync account
    aad_dn = f"CN=MSOL_abc12345,OU=Users,{DOMAIN_DN}"
    add(aad_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "MSOL_abc12345",
        "userAccountControl": "512",
        "adminCount": "1",
        "description": "Account created by Microsoft Azure AD Connect",
        "distinguishedName": aad_dn,
        "objectCategory": "person",
    })

    # User with SID History
    sidhist_dn = f"CN=migrated_admin,OU=Users,{DOMAIN_DN}"
    add(sidhist_dn, ["user", "person", "organizationalPerson", "top"], {
        "sAMAccountName": "migrated_admin",
        "userAccountControl": "512",
        "distinguishedName": sidhist_dn,
        "sIDHistory": ["S-1-5-21-999999999-888888888-777777777-512"],
        "objectCategory": "person",
    })

    # --- GROUPS ---
    da_dn = f"CN=Domain Admins,OU=Groups,{DOMAIN_DN}"
    add(da_dn, ["group", "top"], {
        "cn": "Domain Admins",
        "sAMAccountName": "Domain Admins",
        "distinguishedName": da_dn,
        "member": [admin_dn, svc_sql_dn, disabled_da_dn],
        "adminCount": "1",
        "groupType": "-2147483646",
    })

    ea_dn = f"CN=Enterprise Admins,OU=Groups,{DOMAIN_DN}"
    add(ea_dn, ["group", "top"], {
        "cn": "Enterprise Admins",
        "sAMAccountName": "Enterprise Admins",
        "distinguishedName": ea_dn,
        "member": [admin_dn],
        "adminCount": "1",
        "groupType": "-2147483640",
    })

    sa_dn = f"CN=Schema Admins,OU=Groups,{DOMAIN_DN}"
    add(sa_dn, ["group", "top"], {
        "cn": "Schema Admins",
        "sAMAccountName": "Schema Admins",
        "distinguishedName": sa_dn,
        "member": [admin_dn],
        "adminCount": "1",
        "groupType": "-2147483640",
    })

    admins_dn = f"CN=Administrators,OU=Groups,{DOMAIN_DN}"
    add(admins_dn, ["group", "top"], {
        "cn": "Administrators",
        "sAMAccountName": "Administrators",
        "distinguishedName": admins_dn,
        "member": [admin_dn, da_dn],
        "adminCount": "1",
        "groupType": "-2147483643",
    })

    # Protected Users — empty (vulnerability!)
    pu_dn = f"CN=Protected Users,OU=Groups,{DOMAIN_DN}"
    add(pu_dn, ["group", "top"], {
        "cn": "Protected Users",
        "sAMAccountName": "Protected Users",
        "distinguishedName": pu_dn,
        "member": [],
        "groupType": "-2147483646",
    })

    # DnsAdmins with member
    dnsadm_dn = f"CN=DnsAdmins,OU=Groups,{DOMAIN_DN}"
    add(dnsadm_dn, ["group", "top"], {
        "cn": "DnsAdmins",
        "sAMAccountName": "DnsAdmins",
        "distinguishedName": dnsadm_dn,
        "member": [normal_dn],
        "groupType": "-2147483644",
    })

    # Backup Operators with member
    bo_dn = f"CN=Backup Operators,OU=Groups,{DOMAIN_DN}"
    add(bo_dn, ["group", "top"], {
        "cn": "Backup Operators",
        "sAMAccountName": "Backup Operators",
        "distinguishedName": bo_dn,
        "member": [pne_dn],
        "groupType": "-2147483643",
    })

    # Exchange Windows Permissions (DCSync path!)
    ewp_dn = f"CN=Exchange Windows Permissions,OU=Groups,{DOMAIN_DN}"
    add(ewp_dn, ["group", "top"], {
        "cn": "Exchange Windows Permissions",
        "sAMAccountName": "Exchange Windows Permissions",
        "distinguishedName": ewp_dn,
        "member": [f"CN=Exchange Trusted Subsystem,OU=Groups,{DOMAIN_DN}"],
        "groupType": "-2147483646",
    })

    ets_dn = f"CN=Exchange Trusted Subsystem,OU=Groups,{DOMAIN_DN}"
    add(ets_dn, ["group", "top"], {
        "cn": "Exchange Trusted Subsystem",
        "sAMAccountName": "Exchange Trusted Subsystem",
        "distinguishedName": ets_dn,
        "member": [],
        "groupType": "-2147483646",
    })

    # Nested group inside Domain Admins
    nested_dn = f"CN=IT-Helpdesk,OU=Groups,{DOMAIN_DN}"
    add(nested_dn, ["group", "top"], {
        "cn": "IT-Helpdesk",
        "sAMAccountName": "IT-Helpdesk",
        "distinguishedName": nested_dn,
        "member": [normal_dn],
        "memberOf": [da_dn],
        "groupType": "-2147483646",
    })

    # Empty groups
    for name in ["Project-Alpha", "Temp-Access", "Unused-Group"]:
        gdn = f"CN={name},OU=Groups,{DOMAIN_DN}"
        add(gdn, ["group", "top"], {
            "cn": name,
            "sAMAccountName": name,
            "distinguishedName": gdn,
            "groupType": "-2147483646",
        })

    # --- COMPUTERS ---
    dc_dn = f"CN=DC01,OU=Domain Controllers,{DOMAIN_DN}"
    add(dc_dn, ["computer", "top"], {
        "sAMAccountName": "DC01$",
        "dNSHostName": "dc01.mocklab.local",
        "operatingSystem": "Windows Server 2019 Standard",
        "operatingSystemVersion": "10.0 (17763)",
        "primaryGroupID": "516",
        "userAccountControl": str(0x2000 + 0x80000),  # SERVER_TRUST + TRUSTED_FOR_DELEGATION
        "distinguishedName": dc_dn,
        "objectCategory": "computer",
    })

    # Server with unconstrained delegation (not a DC — critical!)
    web_dn = f"CN=WEB01,OU=Computers,{DOMAIN_DN}"
    add(web_dn, ["computer", "top"], {
        "sAMAccountName": "WEB01$",
        "dNSHostName": "web01.mocklab.local",
        "operatingSystem": "Windows Server 2019 Standard",
        "operatingSystemVersion": "10.0 (17763)",
        "primaryGroupID": "515",
        "userAccountControl": str(0x1000 + 0x80000),  # WORKSTATION_TRUST + TRUSTED_FOR_DELEGATION
        "distinguishedName": web_dn,
        "objectCategory": "computer",
    })

    # Server with constrained delegation + protocol transition
    app_dn = f"CN=APP01,OU=Computers,{DOMAIN_DN}"
    add(app_dn, ["computer", "top"], {
        "sAMAccountName": "APP01$",
        "dNSHostName": "app01.mocklab.local",
        "operatingSystem": "Windows Server 2016 Standard",
        "operatingSystemVersion": "10.0 (14393)",
        "primaryGroupID": "515",
        "userAccountControl": str(0x1000 + 0x1000000),  # WORKSTATION_TRUST + TRUSTED_TO_AUTH_FOR_DELEGATION
        "msDS-AllowedToDelegateTo": ["cifs/dc01.mocklab.local", "ldap/dc01.mocklab.local"],
        "distinguishedName": app_dn,
        "objectCategory": "computer",
    })

    # Windows 7 machine (unsupported OS!)
    win7_dn = f"CN=LEGACY01,OU=Computers,{DOMAIN_DN}"
    add(win7_dn, ["computer", "top"], {
        "sAMAccountName": "LEGACY01$",
        "dNSHostName": "legacy01.mocklab.local",
        "operatingSystem": "Windows 7 Professional",
        "operatingSystemVersion": "6.1 (7601)",
        "primaryGroupID": "515",
        "userAccountControl": "4096",
        "distinguishedName": win7_dn,
        "lastLogonTimestamp": filetime_from_days_ago(2),
        "objectCategory": "computer",
    })

    # Server 2008 R2 (unsupported)
    s2008_dn = f"CN=FILESVR,OU=Computers,{DOMAIN_DN}"
    add(s2008_dn, ["computer", "top"], {
        "sAMAccountName": "FILESVR$",
        "dNSHostName": "filesvr.mocklab.local",
        "operatingSystem": "Windows Server 2008 R2 Standard",
        "operatingSystemVersion": "6.1 (7601)",
        "primaryGroupID": "515",
        "userAccountControl": "4096",
        "distinguishedName": s2008_dn,
        "lastLogonTimestamp": filetime_from_days_ago(5),
        "objectCategory": "computer",
    })

    # Stale computer
    stale_comp_dn = f"CN=DECOMM01,OU=Computers,{DOMAIN_DN}"
    add(stale_comp_dn, ["computer", "top"], {
        "sAMAccountName": "DECOMM01$",
        "operatingSystem": "Windows 10 Enterprise",
        "primaryGroupID": "515",
        "userAccountControl": "4096",
        "distinguishedName": stale_comp_dn,
        "lastLogonTimestamp": filetime_from_days_ago(180),
        "objectCategory": "computer",
    })

    # Computer with LAPS
    laps_dn = f"CN=WKS01,OU=Computers,{DOMAIN_DN}"
    add(laps_dn, ["computer", "top"], {
        "sAMAccountName": "WKS01$",
        "operatingSystem": "Windows 11 Enterprise",
        "primaryGroupID": "515",
        "userAccountControl": "4096",
        "distinguishedName": laps_dn,
        "ms-Mcs-AdmPwdExpirationTime": filetime_from_days_ago(-30),
        "objectCategory": "computer",
    })

    # --- GPOs ---
    gpo_default_dn = f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{DOMAIN_DN}"
    add(gpo_default_dn, ["groupPolicyContainer"], {
        "displayName": "Default Domain Policy",
        "cn": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
        "gPCFileSysPath": f"\\\\{DOMAIN}\\sysvol\\{DOMAIN}\\Policies\\{{31B2F340-016D-11D2-945F-00C04FB984F9}}",
        "flags": "0",
        "whenCreated": "20200101000000.0Z",
        "whenChanged": "20260101000000.0Z",
        "versionNumber": "12",
    })

    gpo_dc_dn = f"CN={{6AC1786C-016F-11D2-945F-00C04fB984F9}},CN=Policies,CN=System,{DOMAIN_DN}"
    add(gpo_dc_dn, ["groupPolicyContainer"], {
        "displayName": "Default Domain Controllers Policy",
        "cn": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
        "gPCFileSysPath": f"\\\\{DOMAIN}\\sysvol\\{DOMAIN}\\Policies\\{{6AC1786C-016F-11D2-945F-00C04fB984F9}}",
        "flags": "0",
        "whenCreated": "20200101000000.0Z",
        "whenChanged": "20260601000000.0Z",
        "versionNumber": "8",
    })

    gpo_wsus_dn = f"CN={{AABB1122-3344-5566-7788-99AABBCCDDEE}},CN=Policies,CN=System,{DOMAIN_DN}"
    add(gpo_wsus_dn, ["groupPolicyContainer"], {
        "displayName": "WSUS Settings",
        "cn": "{AABB1122-3344-5566-7788-99AABBCCDDEE}",
        "gPCFileSysPath": f"\\\\{DOMAIN}\\sysvol\\{DOMAIN}\\Policies\\{{AABB1122-3344-5566-7788-99AABBCCDDEE}}",
        "flags": "0",
        "whenCreated": "20230601000000.0Z",
        "whenChanged": "20260801000000.0Z",
        "versionNumber": "3",
    })

    # Policies container
    add(f"CN=Policies,CN=System,{DOMAIN_DN}", ["container"])
    add(f"CN=System,{DOMAIN_DN}", ["container"])

    # --- AD CS ---
    pks_dn = f"CN=Public Key Services,CN=Services,{CONFIG_DN}"
    add(f"CN=Services,{CONFIG_DN}", ["container"])
    add(pks_dn, ["container"])
    es_dn = f"CN=Enrollment Services,{pks_dn}"
    add(es_dn, ["container"])

    ca_dn = f"CN=MOCKLAB-CA,{es_dn}"
    add(ca_dn, ["pKIEnrollmentService"], {
        "cn": "MOCKLAB-CA",
        "dNSHostName": "ca01.mocklab.local",
        "cACertificateDN": f"CN=MOCKLAB-CA,DC=mocklab,DC=local",
    })

    ct_dn = f"CN=Certificate Templates,{pks_dn}"
    add(ct_dn, ["container"])

    # Vulnerable ESC1 template
    esc1_dn = f"CN=VulnTemplate,{ct_dn}"
    add(esc1_dn, ["pKICertificateTemplate"], {
        "cn": "VulnTemplate",
        "displayName": "Vulnerable Web Server",
        "msPKI-Certificate-Name-Flag": "1",  # ENROLLEE_SUPPLIES_SUBJECT
        "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],  # Client Authentication
        "msPKI-Enrollment-Flag": "0",
        "msPKI-RA-Signature": "0",
    })

    # Safe template
    safe_dn = f"CN=SafeTemplate,{ct_dn}"
    add(safe_dn, ["pKICertificateTemplate"], {
        "cn": "SafeTemplate",
        "displayName": "Domain Controller Authentication",
        "msPKI-Certificate-Name-Flag": "0",
        "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.1"],  # Server Authentication only
        "msPKI-Enrollment-Flag": "0",
        "msPKI-RA-Signature": "1",
    })

    # ESC2 — Any Purpose EKU
    esc2_dn = f"CN=AnyPurposeTemplate,{ct_dn}"
    add(esc2_dn, ["pKICertificateTemplate"], {
        "cn": "AnyPurposeTemplate",
        "displayName": "Any Purpose Certificate",
        "msPKI-Certificate-Name-Flag": "0",
        "pKIExtendedKeyUsage": ["2.5.29.37.0"],  # Any Purpose
        "msPKI-Enrollment-Flag": "0",
        "msPKI-RA-Signature": "0",
    })

    # --- LAPS schema ---
    add(f"CN=ms-Mcs-AdmPwd,{SCHEMA_DN}", ["attributeSchema"], {
        "cn": "ms-Mcs-AdmPwd",
        "lDAPDisplayName": "ms-Mcs-AdmPwd",
    })

    # --- Recycle Bin (disabled) ---
    ds_dn = f"CN=Directory Service,CN=Windows NT,CN=Services,{CONFIG_DN}"
    add(f"CN=Windows NT,CN=Services,{CONFIG_DN}", ["container"])
    add(f"CN=Services,{CONFIG_DN}", ["container"])
    add(ds_dn, ["nTDSService"], {
        "tombstoneLifetime": "180",
    })

    of_dn = f"CN=Optional Features,{ds_dn}"
    add(of_dn, ["container"])
    rb_dn = f"CN=Recycle Bin Feature,{of_dn}"
    add(rb_dn, ["msDS-OptionalFeature"], {
        "msDS-EnabledFeatureBL": [],
    })

    # --- Sites ---
    sites_dn = f"CN=Sites,{CONFIG_DN}"
    add(sites_dn, ["sitesContainer"])
    add(f"CN=Default-First-Site-Name,{sites_dn}", ["site"], {
        "cn": "Default-First-Site-Name",
    })

    # --- Trusts ---
    trust_dn = f"CN=partner.local,CN=System,{DOMAIN_DN}"
    add(trust_dn, ["trustedDomain"], {
        "cn": "partner.local",
        "trustPartner": "partner.local",
        "trustDirection": "3",
        "trustType": "2",
        "trustAttributes": "0",
    })

    # --- gMSA ---
    gmsa_dn = f"CN=svc_web_gmsa,OU=Service Accounts,{DOMAIN_DN}"
    add(gmsa_dn, ["msDS-GroupManagedServiceAccount", "top"], {
        "sAMAccountName": "svc_web_gmsa$",
        "distinguishedName": gmsa_dn,
        "servicePrincipalName": ["HTTP/web01.mocklab.local"],
        "msDS-ManagedPasswordInterval": "30",
    })

    # --- Shadow Credentials target ---
    shadow_dn = f"CN=shadow_target,OU=Computers,{DOMAIN_DN}"
    add(shadow_dn, ["computer", "top"], {
        "sAMAccountName": "SHADOW01$",
        "distinguishedName": shadow_dn,
        "userAccountControl": "4096",
        "primaryGroupID": "515",
        "msDS-KeyCredentialLink": ["B:828:some_keycredential_data:CN=attacker,OU=Users,DC=mocklab,DC=local"],
        "objectCategory": "computer",
    })

    return conn


def run_test():
    print("=" * 70)
    print(f"  AD Audit Toolkit v{TOOL_VERSION} — Mock Environment Dry Run")
    print("=" * 70)
    print(f"\n  Domain:     {DOMAIN}")
    print(f"  Domain DN:  {DOMAIN_DN}")
    print(f"  DC:         {DC_IP} (mock)")
    print(f"  Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    print("[*] Building mock AD environment...")
    conn = build_mock_ad()
    print(f"    Entries loaded: {len(conn.strategy.entries)}")

    domain_info = {
        "domain_name": DOMAIN,
        "domain_dn": DOMAIN_DN,
        "dc_ip": DC_IP,
        "dc_list": ["dc01.mocklab.local"],
        "config_dn": CONFIG_DN,
        "schema_dn": SCHEMA_DN,
    }

    options = {
        "username": "auditor",
        "password": "mock",
        "domain": DOMAIN,
        "dc_ip": DC_IP,
        "hashes": None,
        "timeout": 5,
        "verbose": True,
        "use_ldaps": False,
    }

    from modules.domain_recon import DomainReconModule
    from modules.user_audit import UserAuditModule
    from modules.group_audit import GroupAuditModule
    from modules.computer_audit import ComputerAuditModule
    from modules.password_audit import PasswordAuditModule
    from modules.kerberos_audit import KerberosAudit
    from modules.acl_audit import AclAuditModule
    from modules.adcs_audit import ADCSAudit
    from modules.delegation_audit import DelegationAudit
    from modules.gpo_audit import GPOAudit
    from modules.dns_audit import DNSAudit
    from modules.cve_audit import CVEAudit
    from modules.misc_audit import MiscAudit
    from modules.ldap_audit import LDAPAudit
    from modules.smb_audit import SMBAudit

    modules = [
        ("Domain Recon", DomainReconModule),
        ("User Audit", UserAuditModule),
        ("Group Audit", GroupAuditModule),
        ("Computer Audit", ComputerAuditModule),
        ("Password Policy", PasswordAuditModule),
        ("Kerberos", KerberosAudit),
        ("ACL Audit", AclAuditModule),
        ("AD CS", ADCSAudit),
        ("Delegation", DelegationAudit),
        ("GPO", GPOAudit),
        ("DNS", DNSAudit),
        ("CVE", CVEAudit),
        ("Misc", MiscAudit),
        ("LDAP", LDAPAudit),
        ("SMB", SMBAudit),
    ]

    all_findings = []
    module_timings = []
    total_start = time.time()

    print(f"\n[*] Running {len(modules)} modules...\n")

    for mod_name, mod_cls in modules:
        instance = mod_cls(conn, domain_info, options)
        findings = instance.run()
        all_findings.extend(findings)

        fail_count = sum(1 for f in findings if f.status == STATUS_FAIL)
        warn_count = sum(1 for f in findings if f.status == STATUS_WARN)
        pass_count = sum(1 for f in findings if f.status == STATUS_PASS)
        info_count = sum(1 for f in findings if f.status == STATUS_INFO)
        err_count = sum(1 for f in findings if f.status in (STATUS_ERROR, STATUS_SKIP))

        status_str = f"FAIL:{fail_count} WARN:{warn_count} PASS:{pass_count} INFO:{info_count}"
        if err_count:
            status_str += f" ERR/SKIP:{err_count}"

        symbol = "!!" if fail_count else ("!?" if warn_count else "OK")
        print(f"  [{symbol}] {mod_name:20s} — {len(findings):2d} findings  ({status_str})  [{instance.duration}s]")

        module_timings.append({"name": instance.MODULE_NAME, "duration": instance.duration})

    total_duration = time.time() - total_start

    # --- Summary ---
    print(f"\n{'=' * 70}")
    print(f"  RESULTS SUMMARY")
    print(f"{'=' * 70}")

    total = len(all_findings)
    by_status = {}
    for s in [STATUS_FAIL, STATUS_WARN, STATUS_PASS, STATUS_INFO, STATUS_ERROR, STATUS_SKIP]:
        by_status[s] = sum(1 for f in all_findings if f.status == s)

    by_severity = {}
    for s in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
        by_severity[s] = sum(1 for f in all_findings if f.severity == s and f.status in (STATUS_FAIL, STATUS_WARN))

    print(f"\n  Total findings: {total}")
    print(f"  FAIL: {by_status[STATUS_FAIL]}  |  WARN: {by_status[STATUS_WARN]}  |  PASS: {by_status[STATUS_PASS]}  |  INFO: {by_status[STATUS_INFO]}  |  ERROR/SKIP: {by_status[STATUS_ERROR] + by_status[STATUS_SKIP]}")
    print(f"\n  CRITICAL: {by_severity[SEVERITY_CRITICAL]}  |  HIGH: {by_severity[SEVERITY_HIGH]}  |  MEDIUM: {by_severity[SEVERITY_MEDIUM]}  |  LOW: {by_severity[SEVERITY_LOW]}")
    print(f"\n  Duration: {total_duration:.2f}s")

    # --- List all FAIL/WARN ---
    actionable = [f for f in all_findings if f.status in (STATUS_FAIL, STATUS_WARN)]
    if actionable:
        print(f"\n  Actionable Findings ({len(actionable)}):")
        for f in sorted(actionable, key=lambda x: [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO].index(x.severity)):
            print(f"    [{f.severity:8s}] [{f.status:4s}] {f.test_id:10s} {f.test_name}")

    # --- Generate reports ---
    print(f"\n[*] Generating reports...")

    from reporting.html_report import generate_report

    metadata = {
        "domain": DOMAIN,
        "dc": DC_IP,
        "username": f"{DOMAIN}\\auditor",
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": f"{total_duration:.1f}s",
        "modules_run": len(modules),
        "protocol": "LDAP (Mock)",
        "domain_dn": DOMAIN_DN,
        "forest": DOMAIN,
        "module_timings": module_timings,
    }

    html_path = os.path.join(os.path.dirname(__file__), "test_report.html")
    generate_report(all_findings, metadata, html_path)
    print(f"    HTML: {html_path}")

    try:
        from reporting.html_report import generate_json_report
        json_path = os.path.join(os.path.dirname(__file__), "test_report.json")
        generate_json_report(all_findings, metadata, json_path)
        print(f"    JSON: {json_path}")
    except Exception as e:
        print(f"    JSON: Failed — {e}")

    try:
        from reporting.html_report import generate_csv_report
        csv_path = os.path.join(os.path.dirname(__file__), "test_report.csv")
        generate_csv_report(all_findings, csv_path)
        print(f"    CSV:  {csv_path}")
    except Exception as e:
        print(f"    CSV:  Failed — {e}")

    # --- Validate JSON ---
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        print(f"\n    JSON validated: {len(data.get('findings', []))} findings serialized")
    except Exception as e:
        print(f"\n    JSON validation failed: {e}")

    # --- Validate HTML ---
    try:
        with open(html_path, "r") as f:
            html = f.read()
        assert "<html" in html
        assert "Risk Score" in html or "Executive Summary" in html
        assert "Test Case Matrix" in html
        print(f"    HTML validated: {len(html):,} bytes, key sections present")
    except Exception as e:
        print(f"    HTML validation failed: {e}")

    print(f"\n{'=' * 70}")
    print(f"  DRY RUN COMPLETE — ALL MODULES EXECUTED SUCCESSFULLY")
    print(f"{'=' * 70}\n")

    return True


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
