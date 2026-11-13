from modules.base import BaseModule, Finding
from config import *


class GroupAuditModule(BaseModule):
    MODULE_NAME = "Group Audit"
    MODULE_DESCRIPTION = "Audits group configurations, nesting, empty groups, and privilege sprawl"

    def execute(self):
        self.all_groups = self._fetch_all_groups()
        self._total_group_count()
        self._empty_groups()
        self._nested_privileged_groups()
        self._large_groups()
        self._groups_with_managers()
        self._builtin_group_membership()
        self._protected_users_coverage()

    def _fetch_all_groups(self):
        return self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=group)",
            attributes=[
                "cn", "distinguishedName", "member", "memberOf",
                "groupType", "managedBy", "adminCount",
                "sAMAccountName", "description", "whenCreated",
            ],
        )

    def _cn(self, entry):
        return str(getattr(entry, "cn", "?"))

    def _dn(self, entry):
        return str(getattr(entry, "distinguishedName", ""))

    def _members(self, entry):
        raw = getattr(entry, "member", None)
        if raw is None:
            return []
        if hasattr(raw, "values"):
            return [str(m) for m in raw.values]
        if hasattr(raw, "value") and raw.value:
            return [str(raw.value)]
        return list(raw) if raw else []

    def _member_of(self, entry):
        raw = getattr(entry, "memberOf", None)
        if raw is None:
            return []
        if hasattr(raw, "values"):
            return [str(m) for m in raw.values]
        if hasattr(raw, "value") and raw.value:
            return [str(raw.value)]
        return list(raw) if raw else []

    # GRP-001
    def _total_group_count(self):
        self.add_finding(
            test_id="GRP-001",
            test_name="Total Group Count",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Total domain groups enumerated.",
            observation=f"Found {len(self.all_groups)} group(s) in the domain.",
        )

    # GRP-002
    def _empty_groups(self):
        found = []
        for g in self.all_groups:
            if not self._members(g):
                found.append(self._cn(g))

        self.add_finding(
            test_id="GRP-002",
            test_name="Empty Groups",
            category=self.MODULE_NAME,
            status=STATUS_INFO if found else STATUS_PASS,
            severity=SEVERITY_LOW if found else SEVERITY_INFO,
            description="Empty groups add complexity without purpose and should be reviewed for cleanup.",
            observation=f"{len(found)} group(s) have no members.",
            affected_objects=found[:100],
            remediation="Review empty groups and remove those that are no longer needed.",
        )

    # GRP-003
    def _nested_privileged_groups(self):
        priv_dns = {}
        for g in self.all_groups:
            if self._cn(g) in PRIVILEGED_GROUPS:
                priv_dns[self._dn(g)] = self._cn(g)

        nested_findings = []
        for g in self.all_groups:
            if self._cn(g) in PRIVILEGED_GROUPS:
                continue
            for parent_dn in self._member_of(g):
                if parent_dn in priv_dns:
                    nested_findings.append(
                        f"{self._cn(g)} -> nested in {priv_dns[parent_dn]}"
                    )

        priv_groups_with_nested = set()
        for g in self.all_groups:
            if self._cn(g) in PRIVILEGED_GROUPS:
                for member_dn in self._members(g):
                    for g2 in self.all_groups:
                        if self._dn(g2) == member_dn and self._cn(g2) not in PRIVILEGED_GROUPS:
                            priv_groups_with_nested.add(self._cn(g))
                            nested_findings.append(
                                f"{self._cn(g2)} is a nested group inside {self._cn(g)}"
                            )

        unique = list(set(nested_findings))
        self.add_finding(
            test_id="GRP-003",
            test_name="Nested Privileged Groups",
            category=self.MODULE_NAME,
            status=STATUS_WARN if unique else STATUS_PASS,
            severity=SEVERITY_HIGH if unique else SEVERITY_INFO,
            description="Nested groups inside privileged groups obscure effective membership and "
                        "make access reviews difficult.",
            observation=f"Found {len(unique)} instance(s) of non-privileged groups nested in privileged groups.",
            affected_objects=unique,
            remediation="Replace nested group memberships with direct user memberships in privileged groups. "
                        "Ensure all privileged group members are individually tracked.",
        )

    # GRP-004
    def _large_groups(self):
        threshold = 500
        found = []
        for g in self.all_groups:
            count = len(self._members(g))
            if count > threshold:
                found.append(f"{self._cn(g)} ({count} members)")

        self.add_finding(
            test_id="GRP-004",
            test_name="Unusually Large Groups",
            category=self.MODULE_NAME,
            status=STATUS_INFO if found else STATUS_PASS,
            severity=SEVERITY_LOW if found else SEVERITY_INFO,
            description="Groups with excessive membership may indicate overly broad access grants.",
            observation=f"{len(found)} group(s) have more than {threshold} members.",
            affected_objects=found,
            remediation="Review large groups for appropriate membership scope. Consider breaking into "
                        "smaller, role-based groups.",
        )

    # GRP-005
    def _groups_with_managers(self):
        managed = 0
        unmanaged_priv = []
        for g in self.all_groups:
            mgr = getattr(g, "managedBy", None)
            has_manager = mgr is not None and mgr.value
            if has_manager:
                managed += 1
            elif self._cn(g) in PRIVILEGED_GROUPS:
                unmanaged_priv.append(self._cn(g))

        self.add_finding(
            test_id="GRP-005",
            test_name="Group Ownership / ManagedBy",
            category=self.MODULE_NAME,
            status=STATUS_WARN if unmanaged_priv else STATUS_INFO,
            severity=SEVERITY_LOW if unmanaged_priv else SEVERITY_INFO,
            description="Privileged groups without a designated manager lack accountability for membership changes.",
            observation=(
                f"{managed}/{len(self.all_groups)} groups have a ManagedBy attribute set. "
                f"{len(unmanaged_priv)} privileged group(s) have no manager."
            ),
            affected_objects=unmanaged_priv,
            remediation="Assign a ManagedBy owner to all privileged groups for access review accountability.",
        )

    # GRP-006
    def _builtin_group_membership(self):
        important_builtins = [
            "Account Operators", "Backup Operators", "Server Operators",
            "Print Operators", "DnsAdmins", "Remote Desktop Users",
            "Group Policy Creator Owners",
        ]
        findings = []
        for g in self.all_groups:
            name = self._cn(g)
            if name in important_builtins:
                members = self._members(g)
                if members:
                    count = len(members)
                    sample = []
                    for m in members[:5]:
                        cn = m.split(",")[0].replace("CN=", "") if "CN=" in m else m
                        sample.append(cn)
                    findings.append(f"{name}: {count} member(s) [{', '.join(sample)}]")

        self.add_finding(
            test_id="GRP-006",
            test_name="Built-in Operator Groups",
            category=self.MODULE_NAME,
            status=STATUS_WARN if findings else STATUS_PASS,
            severity=SEVERITY_MEDIUM if findings else SEVERITY_INFO,
            description="Built-in operator groups (Account Operators, Backup Operators, etc.) grant "
                        "significant privileges and are often overlooked in access reviews.",
            observation=f"{len(findings)} built-in operator group(s) have members." if findings
                        else "No members found in built-in operator groups.",
            affected_objects=findings,
            remediation="Review membership of built-in operator groups. These groups grant local admin "
                        "or dangerous privileges on DCs. Remove unnecessary members.",
        )

    # GRP-007
    def _protected_users_coverage(self):
        def _get_group_member_dns(group_cn):
            for g in self.all_groups:
                if self._cn(g) == group_cn:
                    return self._members(g)
            results = self.ldap_search(
                self.get_domain_dn(),
                f"(&(objectClass=group)(cn={group_cn}))",
                attributes=["member"],
            )
            if results:
                raw = getattr(results[0], "member", None)
                if raw:
                    if hasattr(raw, "values"):
                        return [str(m) for m in raw.values]
                    elif raw.value:
                        return [str(raw.value)]
            return []

        protected_members = set(_get_group_member_dns("Protected Users"))

        priv_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins"]
        all_priv_dns = {}
        for pg in priv_groups:
            for member_dn in _get_group_member_dns(pg):
                cn = member_dn.split(",")[0].replace("CN=", "") if "CN=" in member_dn else member_dn
                if member_dn not in all_priv_dns:
                    all_priv_dns[member_dn] = {"name": cn, "groups": []}
                all_priv_dns[member_dn]["groups"].append(pg)

        not_protected = []
        for dn, info in all_priv_dns.items():
            if dn not in protected_members:
                not_protected.append(
                    f"{info['name']} ({', '.join(info['groups'])}) — NOT in Protected Users"
                )

        total_priv = len(all_priv_dns)
        protected_count = total_priv - len(not_protected)

        if not all_priv_dns:
            self.add_finding(
                test_id="GRP-007",
                test_name="Protected Users Coverage",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Protected Users group prevents NTLM authentication, Kerberos delegation, "
                            "and credential caching for its members.",
                observation="No privileged group members found to check.",
            )
            return

        if not_protected:
            self.add_finding(
                test_id="GRP-007",
                test_name="Protected Users Coverage",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description="The Protected Users group prevents NTLM authentication, Kerberos delegation, "
                            "DES/RC4 encryption, and credential caching. All privileged users should be members.",
                observation=(
                    f"{len(not_protected)}/{total_priv} privileged user(s) are NOT in Protected Users. "
                    f"These accounts are vulnerable to NTLM relay, credential theft, and delegation attacks."
                ),
                affected_objects=not_protected,
                remediation="Add all Domain Admins, Enterprise Admins, and Schema Admins to the "
                            "Protected Users group. Test applications first as Protected Users "
                            "prevents NTLM auth and delegation for those accounts.",
                references=["https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"],
            )
        else:
            self.add_finding(
                test_id="GRP-007",
                test_name="Protected Users Coverage",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="All privileged users (DA/EA/SA) are in the Protected Users group.",
                observation=f"{protected_count}/{total_priv} privileged user(s) are in Protected Users.",
            )
