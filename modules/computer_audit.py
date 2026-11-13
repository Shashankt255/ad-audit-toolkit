from datetime import datetime, timedelta, timezone
from modules.base import BaseModule, Finding
from config import *

UAC_ACCOUNTDISABLE = 0x2
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
UAC_SERVER_TRUST_ACCOUNT = 0x2000

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


class ComputerAuditModule(BaseModule):
    MODULE_NAME = "Computer Audit"
    MODULE_DESCRIPTION = "Audits computer accounts for unsupported OS, stale objects, and delegation issues"

    def execute(self):
        self.all_computers = self._fetch_all_computers()
        self._total_computer_count()
        self._unsupported_os()
        self._stale_computers()
        self._unconstrained_delegation()
        self._machine_account_quota()
        self._computers_without_laps()

    def _fetch_all_computers(self):
        return self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=computer)",
            attributes=[
                "cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                "operatingSystemServicePack", "userAccountControl",
                "lastLogonTimestamp", "pwdLastSet", "whenCreated",
                "distinguishedName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
                "ms-DS-MachineAccountQuota", "servicePrincipalName",
                "msDS-AllowedToDelegateTo",
            ],
        )

    def _cn(self, entry):
        return str(getattr(entry, "cn", "?"))

    def _os(self, entry):
        return str(getattr(entry, "operatingSystem", "N/A"))

    def _get_uac(self, entry):
        raw = getattr(entry, "userAccountControl", None)
        if raw is None:
            return 0
        try:
            return int(raw.value)
        except (ValueError, TypeError):
            return 0

    def _is_disabled(self, entry):
        return bool(self._get_uac(entry) & UAC_ACCOUNTDISABLE)

    def _is_dc(self, entry):
        return bool(self._get_uac(entry) & UAC_SERVER_TRUST_ACCOUNT)

    # CMP-001
    def _total_computer_count(self):
        enabled = [c for c in self.all_computers if not self._is_disabled(c)]
        servers = [c for c in enabled if "server" in self._os(c).lower()]
        workstations = [c for c in enabled if "server" not in self._os(c).lower()]
        dcs = [c for c in enabled if self._is_dc(c)]

        self.add_finding(
            test_id="CMP-001",
            test_name="Computer Account Inventory",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Total computer accounts enumerated by type.",
            observation=(
                f"Total: {len(self.all_computers)} computer(s) "
                f"({len(enabled)} enabled, {len(self.all_computers) - len(enabled)} disabled). "
                f"Servers: {len(servers)}, Workstations: {len(workstations)}, DCs: {len(dcs)}."
            ),
        )

    # CMP-002
    def _unsupported_os(self):
        found = []
        for c in self.all_computers:
            if self._is_disabled(c):
                continue
            os_name = self._os(c).lower()
            for keyword in UNSUPPORTED_OS_KEYWORDS:
                if keyword.lower() in os_name:
                    found.append(f"{self._cn(c)} | {self._os(c)}")
                    break

        self.add_finding(
            test_id="CMP-002",
            test_name="Unsupported / End-of-Life Operating Systems",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found else STATUS_PASS,
            severity=SEVERITY_CRITICAL if found else SEVERITY_INFO,
            description="Systems running end-of-life operating systems no longer receive security updates "
                        "and are vulnerable to known exploits.",
            observation=f"{len(found)} enabled computer(s) running unsupported operating systems.",
            affected_objects=found[:100],
            remediation="Upgrade or decommission systems running unsupported operating systems. "
                        "If immediate upgrade is not possible, isolate them on a restricted network segment.",
        )

    # CMP-003
    def _stale_computers(self):
        threshold = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS_THRESHOLD)
        found = []
        for c in self.all_computers:
            if self._is_disabled(c):
                continue
            raw = getattr(c, "lastLogonTimestamp", None)
            if raw is None or raw.value is None:
                continue
            last_logon = _filetime_to_datetime(raw.value)
            if last_logon and last_logon < threshold:
                days_ago = (datetime.now(timezone.utc) - last_logon).days
                found.append(f"{self._cn(c)} | Last logon: {days_ago} days ago | {self._os(c)}")

        self.add_finding(
            test_id="CMP-003",
            test_name="Stale Computer Accounts",
            category=self.MODULE_NAME,
            status=STATUS_WARN if found else STATUS_PASS,
            severity=SEVERITY_LOW if found else SEVERITY_INFO,
            description=f"Computer accounts inactive for {STALE_DAYS_THRESHOLD}+ days may represent "
                        "decommissioned systems that still have valid domain credentials.",
            observation=f"{len(found)} enabled computer account(s) have not logged in for over {STALE_DAYS_THRESHOLD} days.",
            affected_objects=found[:100],
            remediation="Disable or delete stale computer accounts. Implement automated lifecycle management.",
        )

    # CMP-004
    def _unconstrained_delegation(self):
        found = []
        for c in self.all_computers:
            if self._is_disabled(c):
                continue
            uac = self._get_uac(c)
            if uac & UAC_TRUSTED_FOR_DELEGATION and not self._is_dc(c):
                found.append(f"{self._cn(c)} | {self._os(c)}")

        self.add_finding(
            test_id="CMP-004",
            test_name="Unconstrained Delegation (Computers)",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found else STATUS_PASS,
            severity=SEVERITY_CRITICAL if found else SEVERITY_INFO,
            description="Computers with unconstrained delegation cache TGTs of all authenticating users, "
                        "enabling credential theft and lateral movement.",
            observation=f"{len(found)} non-DC computer(s) have unconstrained delegation enabled.",
            affected_objects=found,
            remediation="Replace unconstrained delegation with constrained delegation or "
                        "resource-based constrained delegation. Only DCs should have unconstrained delegation.",
            references=["https://attack.mitre.org/techniques/T1558/"],
        )

    # CMP-005
    def _machine_account_quota(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domain)",
            attributes=["ms-DS-MachineAccountQuota"],
            search_scope="BASE",
        )
        quota = 10
        if entries:
            raw = getattr(entries[0], "ms-DS-MachineAccountQuota", None)
            if raw is not None:
                try:
                    quota = int(raw.value)
                except (ValueError, TypeError):
                    pass

        self.add_finding(
            test_id="CMP-005",
            test_name="Machine Account Quota (MAQ)",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if quota > 0 else STATUS_PASS,
            severity=SEVERITY_MEDIUM if quota > 0 else SEVERITY_INFO,
            description="The default MAQ of 10 allows any authenticated user to join machines to the domain, "
                        "enabling abuse for relay attacks and resource-based constrained delegation.",
            observation=f"ms-DS-MachineAccountQuota = {quota}."
                        + (" Any authenticated user can add machines to the domain." if quota > 0 else ""),
            remediation="Set ms-DS-MachineAccountQuota to 0 and delegate machine join to specific accounts.",
            references=["https://www.thehacker.recipes/ad/movement/domain-settings/machineaccountquota"],
        )

    # CMP-006
    def _computers_without_laps(self):
        found_no_laps = []
        found_laps = []
        for c in self.all_computers:
            if self._is_disabled(c) or self._is_dc(c):
                continue
            laps_pwd = getattr(c, "ms-Mcs-AdmPwd", None)
            laps_exp = getattr(c, "ms-Mcs-AdmPwdExpirationTime", None)
            has_laps = (laps_pwd is not None and laps_pwd.value) or \
                       (laps_exp is not None and laps_exp.value)
            if has_laps:
                found_laps.append(self._cn(c))
            else:
                found_no_laps.append(f"{self._cn(c)} | {self._os(c)}")

        total_checked = len(found_laps) + len(found_no_laps)
        coverage = (len(found_laps) / total_checked * 100) if total_checked > 0 else 0

        self.add_finding(
            test_id="CMP-006",
            test_name="LAPS Deployment Coverage",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if found_no_laps else STATUS_PASS,
            severity=SEVERITY_HIGH if coverage < 50 else (SEVERITY_MEDIUM if found_no_laps else SEVERITY_INFO),
            description="LAPS (Local Administrator Password Solution) randomizes local admin passwords. "
                        "Without LAPS, compromising one local admin password grants access to all machines "
                        "using the same password.",
            observation=(
                f"LAPS coverage: {len(found_laps)}/{total_checked} ({coverage:.0f}%). "
                f"{len(found_no_laps)} computer(s) without LAPS."
            ),
            affected_objects=found_no_laps[:100],
            remediation="Deploy Microsoft LAPS (or Windows LAPS) to all domain-joined workstations and "
                        "member servers. Ensure GPO is configured to enforce LAPS password rotation.",
        )
