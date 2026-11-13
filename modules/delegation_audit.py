from modules.base import BaseModule, Finding
from config import *


class DelegationAudit(BaseModule):
    MODULE_NAME = "Delegation Audit"
    MODULE_DESCRIPTION = "Checks for dangerous Kerberos delegation configurations"

    def execute(self):
        self._check_unconstrained_computers()
        self._check_unconstrained_users()
        self._check_constrained_delegation()
        self._check_protocol_transition()
        self._check_rbcd()
        self._check_delegation_to_privileged_services()

    def _get_dc_names(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["cn", "dNSHostName"],
        )
        names = set()
        for e in entries:
            if hasattr(e, "cn"):
                names.add(str(e.cn).upper())
            if hasattr(e, "dNSHostName") and e.dNSHostName.value:
                names.add(str(e.dNSHostName).upper())
        return names

    def _check_unconstrained_computers(self):
        dc_names = self._get_dc_names()
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            ["cn", "dNSHostName", "sAMAccountName", "userAccountControl", "distinguishedName"],
        )
        non_dc = []
        for e in entries:
            cn = str(e.cn).upper() if hasattr(e, "cn") else ""
            dns_name = str(e.dNSHostName).upper() if hasattr(e, "dNSHostName") and e.dNSHostName.value else ""
            if cn not in dc_names and dns_name not in dc_names:
                non_dc.append(str(e.entry_dn))

        if non_dc:
            self.add_finding(
                test_id="DEL-001",
                test_name="Unconstrained Delegation on Computers",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Non-DC computers with unconstrained delegation can impersonate any user authenticating to them, enabling full domain compromise.",
                observation=f"{len(non_dc)} non-DC computer(s) have unconstrained delegation enabled.",
                remediation="Remove the TRUSTED_FOR_DELEGATION flag from these computers or migrate to constrained delegation. Only DCs should have unconstrained delegation.",
                affected_objects=non_dc,
                references=["https://attack.mitre.org/techniques/T1558/"],
            )
        else:
            self.add_finding(
                test_id="DEL-001",
                test_name="Unconstrained Delegation on Computers",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No non-DC computers with unconstrained delegation found.",
                observation="Only domain controllers have unconstrained delegation, which is expected.",
            )

    def _check_unconstrained_users(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            ["sAMAccountName", "distinguishedName"],
        )
        affected = [str(e.entry_dn) for e in entries]
        if affected:
            self.add_finding(
                test_id="DEL-002",
                test_name="Unconstrained Delegation on User Accounts",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="User accounts with unconstrained delegation can capture and reuse any TGT presented to them, enabling domain compromise.",
                observation=f"{len(affected)} user account(s) have unconstrained delegation enabled.",
                remediation="Remove the TRUSTED_FOR_DELEGATION flag from user accounts. Use constrained delegation or RBCD instead.",
                affected_objects=affected,
                references=["https://attack.mitre.org/techniques/T1558/"],
            )
        else:
            self.add_finding(
                test_id="DEL-002",
                test_name="Unconstrained Delegation on User Accounts",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No user accounts with unconstrained delegation found.",
                observation="User accounts are not configured with unconstrained delegation.",
            )

    def _check_constrained_delegation(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(msDS-AllowedToDelegateTo=*)",
            ["sAMAccountName", "msDS-AllowedToDelegateTo", "objectCategory", "distinguishedName"],
        )
        affected = []
        details_list = []
        for e in entries:
            targets = e["msDS-AllowedToDelegateTo"].values if hasattr(e, "msDS-AllowedToDelegateTo") else []
            affected.append(str(e.entry_dn))
            details_list.append({"account": str(e.sAMAccountName), "targets": list(targets)})

        if affected:
            self.add_finding(
                test_id="DEL-003",
                test_name="Constrained Delegation Configured",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_MEDIUM,
                description="Accounts with constrained delegation can request service tickets to specific services on behalf of any user.",
                observation=f"{len(affected)} account(s) have constrained delegation configured.",
                remediation="Review constrained delegation targets and ensure they follow least privilege. Remove unused delegations.",
                affected_objects=affected,
                details={"delegations": details_list},
                references=["https://attack.mitre.org/techniques/T1558/"],
            )
        else:
            self.add_finding(
                test_id="DEL-003",
                test_name="Constrained Delegation Configured",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No accounts with constrained delegation found.",
                observation="No msDS-AllowedToDelegateTo attributes are set.",
            )

    def _check_protocol_transition(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(userAccountControl:1.2.840.113556.1.4.803:=16777216)",
            ["sAMAccountName", "msDS-AllowedToDelegateTo", "distinguishedName"],
        )
        affected = []
        for e in entries:
            targets = list(e["msDS-AllowedToDelegateTo"].values) if hasattr(e, "msDS-AllowedToDelegateTo") and e["msDS-AllowedToDelegateTo"].value else []
            affected.append({"dn": str(e.entry_dn), "account": str(e.sAMAccountName), "targets": targets})

        if affected:
            self.add_finding(
                test_id="DEL-004",
                test_name="Protocol Transition (T2A4D) Enabled",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description="Accounts with TRUSTED_TO_AUTH_FOR_DELEGATION can perform S4U2Self to obtain a forwardable ticket for any user without that user authenticating, then use S4U2Proxy to access the delegated services.",
                observation=f"{len(affected)} account(s) have protocol transition (T2A4D) enabled.",
                remediation="Remove TRUSTED_TO_AUTH_FOR_DELEGATION where not strictly required. Add sensitive accounts to the 'Protected Users' group or mark them as 'Account is sensitive and cannot be delegated'.",
                affected_objects=[a["dn"] for a in affected],
                details={"accounts": affected},
            )
        else:
            self.add_finding(
                test_id="DEL-004",
                test_name="Protocol Transition (T2A4D) Enabled",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No accounts with protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION) found.",
                observation="Protocol transition is not enabled on any account.",
            )

    def _check_rbcd(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            ["sAMAccountName", "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )
        affected = [str(e.entry_dn) for e in entries]
        if affected:
            self.add_finding(
                test_id="DEL-005",
                test_name="Resource-Based Constrained Delegation (RBCD)",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description="Objects with msDS-AllowedToActOnBehalfOfOtherIdentity allow specified accounts to impersonate users to them. If an attacker controls the allowed account, they can compromise the target.",
                observation=f"{len(affected)} object(s) have RBCD configured.",
                remediation="Review RBCD configurations. Ensure only intended service accounts are listed and that the allowed accounts are well-protected.",
                affected_objects=affected,
                references=["https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-target-exploitation"],
            )
        else:
            self.add_finding(
                test_id="DEL-005",
                test_name="Resource-Based Constrained Delegation (RBCD)",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No objects with RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) found.",
                observation="RBCD is not configured on any object.",
            )

    def _check_delegation_to_privileged_services(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(msDS-AllowedToDelegateTo=*)",
            ["sAMAccountName", "msDS-AllowedToDelegateTo", "distinguishedName"],
        )
        dc_names = self._get_dc_names()
        dangerous_prefixes = ["krbtgt/", "ldap/", "cifs/", "http/", "host/"]
        flagged = []
        for e in entries:
            targets = e["msDS-AllowedToDelegateTo"].values if hasattr(e, "msDS-AllowedToDelegateTo") else []
            dangerous_targets = []
            for t in targets:
                t_upper = str(t).upper()
                for prefix in dangerous_prefixes:
                    if t_upper.startswith(prefix.upper()):
                        svc_host = t_upper.split("/")[1].split(":")[0].split(".")[0] if "/" in t_upper else ""
                        if prefix.upper() == "KRBTGT/" or svc_host in dc_names:
                            dangerous_targets.append(str(t))
            if dangerous_targets:
                flagged.append({
                    "account": str(e.sAMAccountName),
                    "dn": str(e.entry_dn),
                    "dangerous_targets": dangerous_targets,
                })

        if flagged:
            self.add_finding(
                test_id="DEL-006",
                test_name="Delegation to Privileged Services",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Accounts delegated to privileged services (krbtgt, ldap/cifs/host on DCs) can be abused to escalate to Domain Admin via S4U2Proxy attacks.",
                observation=f"{len(flagged)} account(s) are delegated to privileged services on domain controllers.",
                remediation="Remove delegation to krbtgt and DC services. Use least-privilege delegation targets.",
                affected_objects=[f["dn"] for f in flagged],
                details={"flagged_accounts": flagged},
            )
        else:
            self.add_finding(
                test_id="DEL-006",
                test_name="Delegation to Privileged Services",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No constrained delegation to privileged DC services found.",
                observation="No accounts are delegated to krbtgt or sensitive DC services.",
            )
