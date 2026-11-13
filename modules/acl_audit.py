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
        self._shadow_credentials()

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
        try:
            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
            sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
            if not sd['Dacl']:
                return []
            aces = sd['Dacl']['Data']
            holders = {}
            for ace in aces:
                ace_data = ace['Ace']
                if not hasattr(ace_data, 'fields') or 'Sid' not in ace_data.fields:
                    continue
                sid = ace_data['Sid'].formatCanonical()
                if any(sid.startswith(safe) for safe in SAFE_TRUSTEE_PATTERNS):
                    continue
                if sid.endswith("-500") or sid.endswith("-502") or sid.endswith("-516") or sid.endswith("-519") or sid.endswith("-512"):
                    continue
                mask = ace_data['Mask']['Mask']
                if mask & ADS_RIGHT_GENERIC_ALL:
                    holders[sid] = holders.get(sid, set())
                    holders[sid].add("GenericAll (includes DCSync)")
                    continue
                if mask & ADS_RIGHT_DS_CONTROL_ACCESS:
                    object_type = None
                    if hasattr(ace_data, 'fields') and 'ObjectType' in ace_data.fields:
                        raw = ace_data['ObjectType']
                        if raw and len(raw) == 16:
                            import uuid
                            object_type = str(uuid.UUID(bytes_le=bytes(raw)))
                    if object_type and object_type.lower() in [g.lower() for g in DCSYNC_RIGHTS]:
                        holders[sid] = holders.get(sid, set())
                        holders[sid].add(DCSYNC_RIGHTS.get(object_type.lower(), object_type))
            dcsync_principals = []
            for sid, rights in holders.items():
                label = WELL_KNOWN_SIDS.get(sid, sid)
                if "GenericAll (includes DCSync)" in rights or len(rights) >= 2:
                    dcsync_principals.append(f"{label} [{', '.join(rights)}]")
            return dcsync_principals
        except Exception:
            return []

    def _check_dcsync_via_users(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectClass=user)(objectCategory=person)(adminCount=1)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attributes=["sAMAccountName", "distinguishedName", "memberOf"],
        )
        if not entries:
            return []
        default_priv_groups = {"Domain Admins", "Enterprise Admins", "Administrators"}
        suspect = []
        for u in entries:
            sam = str(getattr(u, "sAMAccountName", "?"))
            if sam.lower() in ("administrator", "krbtgt"):
                continue
            member_of_raw = getattr(u, "memberOf", None)
            groups = []
            if member_of_raw:
                if hasattr(member_of_raw, "values"):
                    groups = [str(v) for v in member_of_raw.values]
                elif member_of_raw.value:
                    groups = [str(member_of_raw.value)]
            in_default = any(
                any(dg.lower() in g.lower() for dg in default_priv_groups)
                for g in groups
            )
            if not in_default:
                suspect.append(f"{sam} (adminCount=1, not in default priv groups — possible DCSync delegate)")
        return suspect

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

    # ACL-004
    def _shadow_credentials(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(msDS-KeyCredentialLink=*)",
            attributes=["sAMAccountName", "objectClass", "msDS-KeyCredentialLink"],
        )

        if not entries:
            self.add_finding(
                test_id="ACL-004",
                test_name="Shadow Credentials",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Shadow Credentials abuse the msDS-KeyCredentialLink attribute to associate "
                            "rogue keys with accounts, enabling authentication without knowing the password.",
                observation="No objects with msDS-KeyCredentialLink values found.",
            )
            return

        affected = []
        for entry in entries:
            sam = str(getattr(entry, "sAMAccountName", "?"))
            obj_class_raw = getattr(entry, "objectClass", None)
            obj_class = ""
            if obj_class_raw:
                if hasattr(obj_class_raw, "values"):
                    classes = [str(c) for c in obj_class_raw.values]
                    obj_class = classes[-1] if classes else "unknown"
                elif obj_class_raw.value:
                    obj_class = str(obj_class_raw.value)
            kcl_raw = getattr(entry, "msDS-KeyCredentialLink", None)
            kcl_count = 0
            if kcl_raw:
                if hasattr(kcl_raw, "values"):
                    kcl_count = len(list(kcl_raw.values))
                elif kcl_raw.value:
                    kcl_count = 1
            affected.append(f"{sam} ({obj_class}, {kcl_count} key credential(s))")

        self.add_finding(
            test_id="ACL-004",
            test_name="Shadow Credentials",
            category=self.MODULE_NAME,
            status=STATUS_WARN,
            severity=SEVERITY_MEDIUM,
            description="msDS-KeyCredentialLink values found. These may represent legitimate Windows Hello "
                        "for Business (WHfB) enrollments or could indicate Shadow Credential abuse. "
                        "An attacker with write access to this attribute can authenticate as the target.",
            observation=f"{len(affected)} object(s) have msDS-KeyCredentialLink set.",
            affected_objects=affected,
            remediation="Verify all msDS-KeyCredentialLink entries correspond to legitimate WHfB enrollments. "
                        "Audit write permissions on this attribute — only authorized principals should be able "
                        "to modify it. Use tools like pyWhisker or Whisker to inspect key details.",
            references=["https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab"],
        )
