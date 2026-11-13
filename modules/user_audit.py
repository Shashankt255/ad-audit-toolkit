from datetime import datetime, timedelta, timezone
from modules.base import BaseModule, Finding
from config import *

UAC_ACCOUNTDISABLE = 0x2
UAC_PASSWD_NOTREQD = 0x20
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x80
UAC_NORMAL_ACCOUNT = 0x200
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_DONT_REQ_PREAUTH = 0x400000

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_datetime(ft):
    if ft is None or ft == 0:
        return None
    try:
        val = int(ft)
        if val <= 0:
            return None
        return WINDOWS_EPOCH + timedelta(microseconds=val // 10)
    except (ValueError, OverflowError):
        return None


class UserAuditModule(BaseModule):
    MODULE_NAME = "User Audit"
    MODULE_DESCRIPTION = "Audits user accounts for security misconfigurations and risky attributes"

    def execute(self):
        self.all_users = self._fetch_all_users()
        self.priv_members = self._fetch_privileged_members()
        self._total_user_count()
        self._privileged_users()
        self._password_never_expires()
        self._reversible_encryption()
        self._asrep_roastable()
        self._disabled_in_priv_groups()
        self._stale_accounts()
        self._stale_admincount()
        self._kerberoastable()
        self._empty_password_allowed()
        self._password_not_required()
        self._service_accounts_in_priv()

    def _fetch_all_users(self):
        return self.ldap_search(
            self.get_domain_dn(),
            "(&(objectClass=user)(objectCategory=person))",
            attributes=[
                "sAMAccountName", "distinguishedName", "userAccountControl",
                "memberOf", "adminCount", "servicePrincipalName",
                "lastLogonTimestamp", "pwdLastSet", "whenCreated",
                "description", "cn",
            ],
        )

    def _fetch_privileged_members(self):
        members = {}
        for group_name in PRIVILEGED_GROUPS:
            entries = self.ldap_search(
                self.get_domain_dn(),
                f"(&(objectClass=group)(cn={group_name}))",
                attributes=["member", "distinguishedName"],
            )
            if entries:
                raw = getattr(entries[0], "member", [])
                member_list = list(raw.values) if hasattr(raw, "values") else (list(raw) if raw else [])
                members[group_name] = [str(m) for m in member_list]
            else:
                members[group_name] = []
        return members

    def _get_uac(self, entry):
        raw = getattr(entry, "userAccountControl", None)
        if raw is None:
            return 0
        try:
            return int(raw.value)
        except (ValueError, TypeError):
            return 0

    def _sam(self, entry):
        return str(getattr(entry, "sAMAccountName", "?"))

    def _dn(self, entry):
        return str(getattr(entry, "distinguishedName", ""))

    def _is_disabled(self, entry):
        return bool(self._get_uac(entry) & UAC_ACCOUNTDISABLE)

    def _all_priv_dns(self):
        dns = set()
        for members in self.priv_members.values():
            dns.update(members)
        return dns

    # USR-001
    def _total_user_count(self):
        enabled = [u for u in self.all_users if not self._is_disabled(u)]
        disabled = len(self.all_users) - len(enabled)
        self.add_finding(
            test_id="USR-001",
            test_name="Total User Count",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Total domain user accounts enumerated.",
            observation=f"Total: {len(self.all_users)} users ({len(enabled)} enabled, {disabled} disabled).",
        )

    # USR-002
    def _privileged_users(self):
        da_members = self.priv_members.get("Domain Admins", [])
        ea_members = self.priv_members.get("Enterprise Admins", [])
        sa_members = self.priv_members.get("Schema Admins", [])

        affected = []
        for group_name, members in self.priv_members.items():
            if members:
                for m in members:
                    cn = m.split(",")[0].replace("CN=", "") if "CN=" in m else m
                    affected.append(f"{group_name}: {cn}")

        excessive = len(da_members) > 5
        self.add_finding(
            test_id="USR-002",
            test_name="Privileged Users",
            category=self.MODULE_NAME,
            status=STATUS_WARN if excessive else STATUS_INFO,
            severity=SEVERITY_HIGH if excessive else SEVERITY_INFO,
            description="Excessive privileged accounts increase the attack surface for credential theft.",
            observation=(
                f"Domain Admins: {len(da_members)}, Enterprise Admins: {len(ea_members)}, "
                f"Schema Admins: {len(sa_members)}."
                + (" Domain Admins exceeds recommended maximum of 5." if excessive else "")
            ),
            affected_objects=affected,
            remediation="Reduce Domain Admins to 5 or fewer. Use tiered administration and "
                        "just-in-time privileged access." if excessive else "",
        )

    # USR-003
    def _password_never_expires(self):
        found = []
        for u in self.all_users:
            if self._is_disabled(u):
                continue
            if self._get_uac(u) & UAC_DONT_EXPIRE_PASSWD:
                found.append(self._sam(u))

        self.add_finding(
            test_id="USR-003",
            test_name="Password Never Expires",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found else STATUS_PASS,
            severity=SEVERITY_MEDIUM if found else SEVERITY_INFO,
            description="Accounts with non-expiring passwords weaken the credential rotation posture.",
            observation=f"{len(found)} enabled account(s) have 'Password Never Expires' set.",
            affected_objects=found[:100],
            remediation="Remove the 'Password Never Expires' flag and enforce password rotation via policy.",
        )

    # USR-004
    def _reversible_encryption(self):
        found = []
        for u in self.all_users:
            if self._get_uac(u) & UAC_ENCRYPTED_TEXT_PWD_ALLOWED:
                found.append(self._sam(u))

        self.add_finding(
            test_id="USR-004",
            test_name="Reversible Encryption",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found else STATUS_PASS,
            severity=SEVERITY_CRITICAL if found else SEVERITY_INFO,
            description="Reversible encryption stores passwords in a recoverable form, equivalent to plaintext.",
            observation=f"{len(found)} account(s) have reversible encryption enabled.",
            affected_objects=found,
            remediation="Disable 'Store passwords using reversible encryption' and reset affected passwords.",
        )

    # USR-005
    def _asrep_roastable(self):
        found = []
        for u in self.all_users:
            if self._is_disabled(u):
                continue
            if self._get_uac(u) & UAC_DONT_REQ_PREAUTH:
                found.append(self._sam(u))

        self.add_finding(
            test_id="USR-005",
            test_name="AS-REP Roastable Accounts",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found else STATUS_PASS,
            severity=SEVERITY_HIGH if found else SEVERITY_INFO,
            description="Accounts without Kerberos pre-authentication can have their password hashes "
                        "retrieved offline (AS-REP roasting).",
            observation=f"{len(found)} enabled account(s) do not require Kerberos pre-authentication.",
            affected_objects=found,
            remediation="Enable Kerberos pre-authentication for all accounts. Use strong, long passwords "
                        "for any accounts that must remain without pre-auth.",
            references=["https://attack.mitre.org/techniques/T1558/004/"],
        )

    # USR-006
    def _disabled_in_priv_groups(self):
        priv_dns = self._all_priv_dns()
        found = []
        for u in self.all_users:
            if self._is_disabled(u) and self._dn(u) in priv_dns:
                found.append(self._sam(u))

        self.add_finding(
            test_id="USR-006",
            test_name="Disabled Accounts in Privileged Groups",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found else STATUS_PASS,
            severity=SEVERITY_MEDIUM if found else SEVERITY_INFO,
            description="Disabled accounts left in privileged groups could be re-enabled for privilege escalation.",
            observation=f"{len(found)} disabled account(s) remain in privileged groups.",
            affected_objects=found,
            remediation="Remove disabled accounts from all privileged groups immediately.",
        )

    # USR-007
    def _stale_accounts(self):
        threshold = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS_THRESHOLD)
        found = []
        for u in self.all_users:
            if self._is_disabled(u):
                continue
            raw = getattr(u, "lastLogonTimestamp", None)
            if raw is None or raw.value is None:
                continue
            last_logon = _filetime_to_datetime(raw.value)
            if last_logon and last_logon < threshold:
                found.append(self._sam(u))

        self.add_finding(
            test_id="USR-007",
            test_name="Stale/Inactive Accounts",
            category=self.MODULE_NAME,
            status=STATUS_WARN if found else STATUS_PASS,
            severity=SEVERITY_LOW if found else SEVERITY_INFO,
            description=f"Accounts with no logon in {STALE_DAYS_THRESHOLD}+ days are potential targets.",
            observation=f"{len(found)} enabled account(s) have not logged in for over {STALE_DAYS_THRESHOLD} days.",
            affected_objects=found[:100],
            remediation="Disable or remove stale accounts. Implement an automated account lifecycle process.",
        )

    # USR-008
    def _stale_admincount(self):
        priv_dns = self._all_priv_dns()
        found = []
        for u in self.all_users:
            ac = getattr(u, "adminCount", None)
            if ac is not None and str(ac.value) == "1":
                if self._dn(u) not in priv_dns:
                    found.append(self._sam(u))

        self.add_finding(
            test_id="USR-008",
            test_name="Stale AdminCount",
            category=self.MODULE_NAME,
            status=STATUS_WARN if found else STATUS_PASS,
            severity=SEVERITY_LOW if found else SEVERITY_INFO,
            description="AdminCount=1 on users no longer in privileged groups prevents ACL inheritance, "
                        "causing security descriptor mismatches.",
            observation=f"{len(found)} user(s) have AdminCount=1 but are not in any privileged group.",
            affected_objects=found[:100],
            remediation="Clear AdminCount and re-enable inheritance on affected objects. "
                        "Run the AdminSDHolder cleanup procedure.",
        )

    # USR-009
    def _kerberoastable(self):
        found = []
        priv_dns = self._all_priv_dns()
        priv_kerberoastable = []
        for u in self.all_users:
            if self._is_disabled(u):
                continue
            spn = getattr(u, "servicePrincipalName", None)
            if spn is None:
                continue
            vals = list(spn.values) if hasattr(spn, "values") else ([spn.value] if spn.value else [])
            if vals:
                sam = self._sam(u)
                found.append(f"{sam} (SPNs: {', '.join(str(v) for v in vals[:3])})")
                if self._dn(u) in priv_dns:
                    priv_kerberoastable.append(sam)

        severity = SEVERITY_CRITICAL if priv_kerberoastable else (SEVERITY_HIGH if found else SEVERITY_INFO)
        obs = f"{len(found)} enabled user account(s) have SPNs set (Kerberoastable)."
        if priv_kerberoastable:
            obs += f" {len(priv_kerberoastable)} of these are in privileged groups: {', '.join(priv_kerberoastable)}."

        self.add_finding(
            test_id="USR-009",
            test_name="Kerberoastable Accounts",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found else STATUS_PASS,
            severity=severity,
            description="User accounts with SPNs can have their Kerberos service tickets requested and cracked "
                        "offline (Kerberoasting).",
            observation=obs,
            affected_objects=found[:100],
            remediation="Use Group Managed Service Accounts (gMSA) instead of user accounts with SPNs. "
                        "For remaining SPNs, enforce 25+ character passwords and AES-only encryption.",
            references=["https://attack.mitre.org/techniques/T1558/003/"],
        )

    # USR-010
    def _empty_password_allowed(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectClass=domain))",
            attributes=["minPwdLength"],
            search_scope="BASE",
        )
        min_len = 0
        if entries:
            raw = getattr(entries[0], "minPwdLength", None)
            if raw is not None:
                min_len = int(raw.value)

        self.add_finding(
            test_id="USR-010",
            test_name="Empty Password Allowed",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if min_len == 0 else STATUS_PASS,
            severity=SEVERITY_CRITICAL if min_len == 0 else SEVERITY_INFO,
            description="A minimum password length of 0 allows empty passwords.",
            observation=f"Minimum password length is {min_len}."
                        + (" Empty passwords are allowed!" if min_len == 0 else ""),
            remediation="Set minimum password length to at least 12 characters.",
        )

    # USR-011
    def _password_not_required(self):
        found = []
        for u in self.all_users:
            if self._is_disabled(u):
                continue
            if self._get_uac(u) & UAC_PASSWD_NOTREQD:
                found.append(self._sam(u))

        self.add_finding(
            test_id="USR-011",
            test_name="Password Not Required Flag",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found else STATUS_PASS,
            severity=SEVERITY_HIGH if found else SEVERITY_INFO,
            description="The PASSWD_NOTREQD flag allows accounts to exist without a password, "
                        "bypassing domain password policy.",
            observation=f"{len(found)} enabled account(s) have 'Password Not Required' set.",
            affected_objects=found,
            remediation="Remove the PASSWD_NOTREQD flag from all user accounts and set a strong password.",
        )

    # USR-012
    def _service_accounts_in_priv(self):
        found = []
        priv_dns = self._all_priv_dns()
        svc_patterns = ["svc_", "svc-", "service", "sql", "backup", "iis", "app_", "task_"]
        for u in self.all_users:
            sam = self._sam(u).lower()
            is_svc = any(pat in sam for pat in svc_patterns)
            spn = getattr(u, "servicePrincipalName", None)
            has_spn = spn is not None and (
                (hasattr(spn, "values") and list(spn.values)) or
                (hasattr(spn, "value") and spn.value)
            )
            if (is_svc or has_spn) and self._dn(u) in priv_dns:
                found.append(self._sam(u))

        self.add_finding(
            test_id="USR-012",
            test_name="Service Accounts in Privileged Groups",
            category=self.MODULE_NAME,
            status=STATUS_WARN if found else STATUS_PASS,
            severity=SEVERITY_HIGH if found else SEVERITY_INFO,
            description="Service accounts in privileged groups violate least-privilege and are high-value "
                        "Kerberoasting targets.",
            observation=f"{len(found)} likely service account(s) found in privileged groups.",
            affected_objects=found,
            remediation="Move service accounts out of privileged groups. Use gMSA and delegate only "
                        "the specific permissions required.",
        )
