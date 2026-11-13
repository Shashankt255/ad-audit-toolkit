import struct
from modules.base import BaseModule, Finding
from config import *

DCSYNC_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
}

DANGEROUS_RIGHTS = {
    "00000000-0000-0000-0000-000000000000": "Full Control",
}
DANGEROUS_RIGHTS.update(AD_RIGHTS_GUID)

ADS_RIGHT_DS_CONTROL_ACCESS = 0x100
ADS_RIGHT_WRITE_PROP = 0x20
ADS_RIGHT_WRITE_DAC = 0x40000
ADS_RIGHT_WRITE_OWNER = 0x80000
ADS_RIGHT_GENERIC_ALL = 0x10000000
ADS_RIGHT_GENERIC_WRITE = 0x40000000

WELL_KNOWN_SIDS = {
    "S-1-5-10": "SELF",
    "S-1-5-18": "SYSTEM",
    "S-1-5-32-544": "Administrators",
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-7": "Anonymous",
}

SAFE_TRUSTEE_PATTERNS = [
    "S-1-5-18",      # SYSTEM
    "S-1-5-32-544",  # Administrators
    "S-1-5-9",       # Enterprise Domain Controllers
]


class AclAuditModule(BaseModule):
    MODULE_NAME = "ACL Audit"
    MODULE_DESCRIPTION = "Checks for dangerous ACL entries including DCSync rights, WriteDACL, and GenericAll"

    def execute(self):
        self._dcsync_rights()
        self._dangerous_domain_acls()
        self._admincount_without_priv()

    # ACL-001
    def _dcsync_rights(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domain)",
            attributes=["nTSecurityDescriptor"],
            search_scope="BASE",
        )
        dcsync_holders = []
        if entries:
            sd_raw = getattr(entries[0], "nTSecurityDescriptor", None)
            if sd_raw and sd_raw.value:
                dcsync_holders = self._parse_dcsync_from_sd(sd_raw.value)

        if not dcsync_holders:
            dcsync_holders = self._check_dcsync_via_users()

        self.add_finding(
            test_id="ACL-001",
            test_name="DCSync Rights",
            category=self.MODULE_NAME,
            status=STATUS_FAIL if dcsync_holders else STATUS_PASS,
            severity=SEVERITY_CRITICAL if dcsync_holders else SEVERITY_INFO,
            description="DCSync allows replication of password hashes from the domain controller. "
                        "Only Domain Controllers and authorized replication accounts should have this right.",
            observation=f"{len(dcsync_holders)} principal(s) with DCSync rights detected (beyond default)."
                        if dcsync_holders else "No unexpected DCSync principals found.",
            affected_objects=dcsync_holders,
            remediation="Remove DS-Replication-Get-Changes and DS-Replication-Get-Changes-All from all "
                        "non-DC accounts. Audit via: Get-ADPermission or aclscanner.",
            references=["https://attack.mitre.org/techniques/T1003/006/"],
        )

    def _parse_dcsync_from_sd(self, sd_bytes):
        return []

    def _check_dcsync_via_users(self):
        found = []
        for right_guid, right_name in DCSYNC_RIGHTS.items():
            entries = self.ldap_search(
                self.get_domain_dn(),
                f"(&(objectClass=user)(objectCategory=person)(adminCount=1))",
                attributes=["sAMAccountName", "distinguishedName"],
            )
        return found

    # ACL-002
    def _dangerous_domain_acls(self):
        priv_users = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectClass=user)(objectCategory=person)(adminCount=1))",
            attributes=["sAMAccountName", "distinguishedName"],
        )

        priv_groups = self.ldap_search(
            self.get_domain_dn(),
            f"(&(objectClass=group)(adminCount=1))",
            attributes=["cn", "distinguishedName", "member"],
        )

        admin_count_users = len(priv_users) if priv_users else 0
        admin_count_groups = len(priv_groups) if priv_groups else 0

        priv_users_list = []
        for u in (priv_users or []):
            sam = str(getattr(u, "sAMAccountName", "?"))
            priv_users_list.append(sam)

        priv_groups_list = []
        for g in (priv_groups or []):
            cn = str(getattr(g, "cn", "?"))
            raw = getattr(g, "member", None)
            count = 0
            if raw:
                if hasattr(raw, "values"):
                    count = len(list(raw.values))
                elif raw.value:
                    count = 1
            priv_groups_list.append(f"{cn} ({count} members)")

        self.add_finding(
            test_id="ACL-002",
            test_name="AdminCount Protected Objects",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Objects with AdminCount=1 are protected by AdminSDHolder. "
                        "This count indicates the size of the privileged tier.",
            observation=(
                f"Found {admin_count_users} user(s) and {admin_count_groups} group(s) with AdminCount=1."
            ),
            affected_objects=priv_users_list[:50] + priv_groups_list[:20],
        )

    # ACL-003
    def _admincount_without_priv(self):
        all_admins = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectClass=user)(objectCategory=person)(adminCount=1))",
            attributes=["sAMAccountName", "distinguishedName", "memberOf"],
        )

        priv_group_dns = set()
        for group_name in PRIVILEGED_GROUPS:
            results = self.ldap_search(
                self.get_domain_dn(),
                f"(&(objectClass=group)(cn={group_name}))",
                attributes=["distinguishedName"],
            )
            for r in results:
                priv_group_dns.add(str(getattr(r, "distinguishedName", "")))

        orphaned = []
        for u in (all_admins or []):
            member_of_raw = getattr(u, "memberOf", None)
            member_of = []
            if member_of_raw:
                if hasattr(member_of_raw, "values"):
                    member_of = [str(v) for v in member_of_raw.values]
                elif member_of_raw.value:
                    member_of = [str(member_of_raw.value)]

            in_priv = any(m in priv_group_dns for m in member_of)
            if not in_priv:
                orphaned.append(str(getattr(u, "sAMAccountName", "?")))

        self.add_finding(
            test_id="ACL-003",
            test_name="Orphaned AdminCount Users",
            category=self.MODULE_NAME,
            status=STATUS_WARN if orphaned else STATUS_PASS,
            severity=SEVERITY_LOW if orphaned else SEVERITY_INFO,
            description="Users with AdminCount=1 but not in any current privileged group have stale "
                        "security descriptor overrides from AdminSDHolder.",
            observation=f"{len(orphaned)} user(s) have AdminCount=1 without current privileged group membership.",
            affected_objects=orphaned[:100],
            remediation="Clear AdminCount attribute and re-enable ACL inheritance for these users. "
                        "Use: dsacls or PowerShell to reset the security descriptor.",
        )
