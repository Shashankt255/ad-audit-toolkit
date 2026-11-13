from datetime import datetime, timedelta, timezone
from modules.base import BaseModule, Finding
from config import *


FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_datetime(ft):
    if ft is None or ft == 0:
        return None
    try:
        ft = int(str(ft))
        if ft <= 0:
            return None
        return FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (ValueError, OverflowError):
        return None


class KerberosAudit(BaseModule):
    MODULE_NAME = "Kerberos Audit"
    MODULE_DESCRIPTION = "Checks for Kerberos-related security weaknesses including Kerberoasting, AS-REP roasting, weak encryption, and delegation issues."

    def execute(self):
        self._check_kerberoastable()
        self._check_asrep_roastable()
        self._check_weak_encryption()
        self._check_krbtgt_password_age()
        self._check_krbtgt_aes()
        self._check_delegation_summary()

    def _check_kerberoastable(self):
        search_filter = (
            "(&(objectClass=user)(objectCategory=person)"
            "(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(!(cn=krbtgt)))"
        )
        entries = self.ldap_search(
            self.get_domain_dn(),
            search_filter,
            attributes=["sAMAccountName", "servicePrincipalName", "memberOf", "adminCount", "pwdLastSet"],
        )

        accounts = []
        for entry in entries:
            sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "N/A"
            spns = entry.servicePrincipalName.values if hasattr(entry, "servicePrincipalName") else []
            admin_count = str(entry.adminCount) if hasattr(entry, "adminCount") else "0"
            pwd_last_set = filetime_to_datetime(entry.pwdLastSet.value if hasattr(entry, "pwdLastSet") else 0)
            pwd_age = ""
            if pwd_last_set:
                age = (datetime.now(timezone.utc) - pwd_last_set).days
                pwd_age = f"{age} days"
            accounts.append({
                "sAMAccountName": sam,
                "SPNs": list(spns) if spns else [],
                "adminCount": admin_count,
                "passwordAge": pwd_age,
            })

        if accounts:
            self.add_finding(
                test_id="KRB-001",
                test_name="Kerberoastable Accounts",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description=(
                    "User accounts with Service Principal Names (SPNs) set are vulnerable to "
                    "Kerberoasting. An attacker with any domain user credentials can request "
                    "TGS tickets for these accounts and attempt offline password cracking."
                ),
                observation=f"Found {len(accounts)} Kerberoastable user account(s).",
                remediation=(
                    "Use Group Managed Service Accounts (gMSA) where possible. "
                    "Ensure service accounts use strong, long (25+ character) passwords. "
                    "Set accounts to use AES256 encryption only."
                ),
                affected_objects=[a["sAMAccountName"] for a in accounts],
                details={"accounts": accounts},
                references=[
                    "https://attack.mitre.org/techniques/T1558/003/",
                    "https://adsecurity.org/?p=2293",
                ],
            )
        else:
            self.add_finding(
                test_id="KRB-001",
                test_name="Kerberoastable Accounts",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No enabled user accounts with SPNs found (excluding krbtgt).",
                observation="No Kerberoastable accounts detected.",
            )

    def _check_asrep_roastable(self):
        search_filter = (
            "(&(objectClass=user)(objectCategory=person)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        )
        entries = self.ldap_search(
            self.get_domain_dn(),
            search_filter,
            attributes=["sAMAccountName", "memberOf", "adminCount"],
        )

        accounts = []
        for entry in entries:
            sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "N/A"
            admin_count = str(entry.adminCount) if hasattr(entry, "adminCount") else "0"
            accounts.append({"sAMAccountName": sam, "adminCount": admin_count})

        if accounts:
            self.add_finding(
                test_id="KRB-002",
                test_name="AS-REP Roastable Accounts",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description=(
                    "User accounts with 'Do not require Kerberos preauthentication' enabled "
                    "are vulnerable to AS-REP Roasting. An attacker can request an AS-REP for "
                    "these accounts without knowing their password and crack it offline."
                ),
                observation=f"Found {len(accounts)} AS-REP Roastable account(s).",
                remediation=(
                    "Remove the DONT_REQ_PREAUTH flag from all user accounts unless there "
                    "is a documented business requirement. Ensure affected accounts use "
                    "strong passwords."
                ),
                affected_objects=[a["sAMAccountName"] for a in accounts],
                details={"accounts": accounts},
                references=[
                    "https://attack.mitre.org/techniques/T1558/004/",
                ],
            )
        else:
            self.add_finding(
                test_id="KRB-002",
                test_name="AS-REP Roastable Accounts",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No accounts with Kerberos preauthentication disabled.",
                observation="No AS-REP Roastable accounts detected.",
            )

    def _check_weak_encryption(self):
        search_filter = (
            "(&(objectClass=user)(objectCategory=person)"
            "(msDS-SupportedEncryptionTypes=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        entries = self.ldap_search(
            self.get_domain_dn(),
            search_filter,
            attributes=["sAMAccountName", "msDS-SupportedEncryptionTypes"],
        )

        weak_accounts = []
        for entry in entries:
            sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "N/A"
            raw = entry["msDS-SupportedEncryptionTypes"].value if "msDS-SupportedEncryptionTypes" in entry.entry_attributes else None
            if raw is None:
                continue
            try:
                enc_types = int(str(raw))
            except (ValueError, TypeError):
                continue

            supports_des = bool(enc_types & 0x7)
            supports_rc4 = bool(enc_types & 0x4) or bool(enc_types & 0x8)
            supports_aes128 = bool(enc_types & 0x8) or bool(enc_types & 0x10)
            supports_aes256 = bool(enc_types & 0x10) or bool(enc_types & 0x8)

            des_flag = bool(enc_types & 0x3)
            rc4_flag = bool(enc_types & 0x4)
            aes128_flag = bool(enc_types & 0x8)
            aes256_flag = bool(enc_types & 0x10)

            if des_flag or (rc4_flag and not aes128_flag and not aes256_flag):
                enc_names = []
                if enc_types & 0x1: enc_names.append("DES-CBC-CRC")
                if enc_types & 0x2: enc_names.append("DES-CBC-MD5")
                if enc_types & 0x4: enc_names.append("RC4-HMAC")
                if enc_types & 0x8: enc_names.append("AES128")
                if enc_types & 0x10: enc_names.append("AES256")
                weak_accounts.append({
                    "sAMAccountName": sam,
                    "encryptionTypes": enc_names,
                    "rawValue": enc_types,
                })

        if weak_accounts:
            self.add_finding(
                test_id="KRB-003",
                test_name="Weak Kerberos Encryption Types",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_MEDIUM,
                description=(
                    "Accounts configured to support DES or RC4-only Kerberos encryption "
                    "are vulnerable to faster offline cracking attacks."
                ),
                observation=f"Found {len(weak_accounts)} account(s) with weak encryption.",
                remediation=(
                    "Configure all accounts to support AES256 encryption. Remove DES and "
                    "RC4 support where possible. Set msDS-SupportedEncryptionTypes to 0x18 "
                    "(AES128 + AES256)."
                ),
                affected_objects=[a["sAMAccountName"] for a in weak_accounts],
                details={"accounts": weak_accounts},
            )
        else:
            self.add_finding(
                test_id="KRB-003",
                test_name="Weak Kerberos Encryption Types",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No accounts limited to weak Kerberos encryption types.",
                observation="All checked accounts support AES encryption.",
            )

    def _check_krbtgt_password_age(self):
        search_filter = "(&(objectClass=user)(sAMAccountName=krbtgt))"
        entries = self.ldap_search(
            self.get_domain_dn(),
            search_filter,
            attributes=["pwdLastSet", "whenChanged"],
        )

        if not entries:
            self.add_finding(
                test_id="KRB-004",
                test_name="krbtgt Password Age",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description="Could not query krbtgt account.",
                observation="LDAP query for krbtgt returned no results.",
            )
            return

        entry = entries[0]
        pwd_last_set = filetime_to_datetime(entry.pwdLastSet.value if hasattr(entry, "pwdLastSet") else 0)
        if not pwd_last_set:
            self.add_finding(
                test_id="KRB-004",
                test_name="krbtgt Password Age",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description="Could not determine krbtgt password last set time.",
                observation="pwdLastSet for krbtgt is null or zero.",
            )
            return

        age_days = (datetime.now(timezone.utc) - pwd_last_set).days

        if age_days > 180:
            status, severity = STATUS_FAIL, SEVERITY_CRITICAL
        elif age_days > 90:
            status, severity = STATUS_WARN, SEVERITY_HIGH
        else:
            status, severity = STATUS_PASS, SEVERITY_INFO

        self.add_finding(
            test_id="KRB-004",
            test_name="krbtgt Password Age",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=(
                "The krbtgt account password should be rotated regularly (at least every "
                "180 days). A stale krbtgt password means a Golden Ticket attack remains "
                "viable for an extended period."
            ),
            observation=f"krbtgt password was last set {age_days} days ago ({pwd_last_set.strftime('%Y-%m-%d %H:%M:%S UTC')}).",
            remediation=(
                "Rotate the krbtgt password twice (with a replication interval between resets) "
                "to invalidate all existing Kerberos tickets. Schedule regular rotation."
            ),
            details={"pwdLastSet": pwd_last_set.isoformat(), "ageDays": age_days},
            references=[
                "https://adsecurity.org/?p=483",
                "https://attack.mitre.org/techniques/T1558/001/",
            ],
        )

    def _check_krbtgt_aes(self):
        search_filter = "(&(objectClass=user)(sAMAccountName=krbtgt))"
        entries = self.ldap_search(
            self.get_domain_dn(),
            search_filter,
            attributes=["msDS-SupportedEncryptionTypes"],
        )

        if not entries:
            self.add_finding(
                test_id="KRB-005",
                test_name="krbtgt AES Keys",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description="Could not query krbtgt account encryption types.",
                observation="LDAP query returned no results.",
            )
            return

        entry = entries[0]
        raw = entry["msDS-SupportedEncryptionTypes"].value if "msDS-SupportedEncryptionTypes" in entry.entry_attributes else None

        if raw is None:
            self.add_finding(
                test_id="KRB-005",
                test_name="krbtgt AES Keys",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_MEDIUM,
                description="krbtgt does not have msDS-SupportedEncryptionTypes set explicitly.",
                observation=(
                    "The attribute is not set; the DC will default based on functional level. "
                    "Explicitly setting AES256 is recommended."
                ),
                remediation="Set msDS-SupportedEncryptionTypes on krbtgt to 0x18 (AES128+AES256).",
            )
            return

        try:
            enc_types = int(str(raw))
        except (ValueError, TypeError):
            enc_types = 0

        aes256 = bool(enc_types & 0x10)
        aes128 = bool(enc_types & 0x8)

        if aes256:
            self.add_finding(
                test_id="KRB-005",
                test_name="krbtgt AES Keys",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="krbtgt account supports AES256 encryption.",
                observation=f"msDS-SupportedEncryptionTypes = {enc_types} (AES256 enabled).",
            )
        else:
            self.add_finding(
                test_id="KRB-005",
                test_name="krbtgt AES Keys",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_MEDIUM,
                description="krbtgt does not have AES256 enabled in its encryption types.",
                observation=f"msDS-SupportedEncryptionTypes = {enc_types}.",
                remediation="Enable AES256 on the krbtgt account.",
            )

    def _check_delegation_summary(self):
        unconstrained_filter = (
            "(&(objectCategory=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(primaryGroupID=516)))"
        )
        unconstrained = self.ldap_search(
            self.get_domain_dn(), unconstrained_filter,
            attributes=["sAMAccountName", "dNSHostName"],
        )

        constrained_filter = (
            "(&(objectCategory=*)(msDS-AllowedToDelegateTo=*))"
        )
        constrained = self.ldap_search(
            self.get_domain_dn(), constrained_filter,
            attributes=["sAMAccountName", "msDS-AllowedToDelegateTo"],
        )

        rbcd_filter = (
            "(&(objectCategory=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
        )
        rbcd = self.ldap_search(
            self.get_domain_dn(), rbcd_filter,
            attributes=["sAMAccountName"],
        )

        unconstrained_list = [str(e.sAMAccountName) for e in unconstrained] if unconstrained else []
        constrained_list = [str(e.sAMAccountName) for e in constrained] if constrained else []
        rbcd_list = [str(e.sAMAccountName) for e in rbcd] if rbcd else []

        severity = SEVERITY_INFO
        status = STATUS_INFO
        if unconstrained_list:
            severity = SEVERITY_HIGH
            status = STATUS_WARN

        self.add_finding(
            test_id="KRB-006",
            test_name="Kerberos Delegation Summary",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=(
                "Summary of Kerberos delegation configurations in the domain. "
                "Unconstrained delegation is the most dangerous as it allows a compromised "
                "server to impersonate any user to any service."
            ),
            observation=(
                f"Unconstrained delegation: {len(unconstrained_list)} object(s), "
                f"Constrained delegation: {len(constrained_list)} object(s), "
                f"Resource-Based Constrained Delegation (RBCD): {len(rbcd_list)} object(s)."
            ),
            details={
                "unconstrained": unconstrained_list,
                "constrained": constrained_list,
                "rbcd": rbcd_list,
            },
            remediation=(
                "Replace unconstrained delegation with constrained or RBCD where possible. "
                "Protect accounts with delegation by setting 'Account is sensitive and cannot "
                "be delegated' on high-value targets."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1550/003/",
            ],
        )
