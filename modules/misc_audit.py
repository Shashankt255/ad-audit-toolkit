from modules.base import BaseModule
from config import *


class MiscAudit(BaseModule):
    MODULE_NAME = "Miscellaneous Audit"
    MODULE_DESCRIPTION = "Checks LAPS deployment, MachineAccountQuota, functional level, and Recycle Bin."

    def execute(self):
        self._check_laps()
        self._check_machine_account_quota()
        self._check_functional_level()
        self._check_recycle_bin()

    def _check_laps(self):
        schema_dn = self.domain_info.get("schema_dn", f"CN=Schema,CN=Configuration,{self.get_domain_dn()}")

        legacy_laps = self.ldap_search(
            schema_dn,
            "(&(objectClass=attributeSchema)(cn=ms-Mcs-AdmPwd))",
            attributes=["cn"],
        )
        windows_laps = self.ldap_search(
            schema_dn,
            "(&(objectClass=attributeSchema)(cn=msLAPS-Password))",
            attributes=["cn"],
        )

        laps_deployed = bool(legacy_laps) or bool(windows_laps)
        laps_type = []
        if legacy_laps:
            laps_type.append("Legacy LAPS (ms-Mcs-AdmPwd)")
        if windows_laps:
            laps_type.append("Windows LAPS (msLAPS-Password)")

        if not laps_deployed:
            self.add_finding(
                test_id="MISC-001",
                test_name="LAPS Deployment",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description=(
                    "Local Administrator Password Solution (LAPS) is not deployed. "
                    "Without LAPS, local admin passwords may be reused across machines."
                ),
                observation="Neither Legacy LAPS nor Windows LAPS schema extensions found.",
                remediation=(
                    "Deploy Windows LAPS (built into Windows Server 2019+ with April 2023 update) "
                    "or Legacy LAPS to manage local administrator passwords."
                ),
            )
            return

        computers_with_laps = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))",
            attributes=["sAMAccountName"],
        )
        total_computers = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectCategory=computer)(!(primaryGroupID=516)))",
            attributes=["sAMAccountName"],
        )

        laps_count = len(computers_with_laps) if computers_with_laps else 0
        total_count = len(total_computers) if total_computers else 0
        coverage = f"{laps_count}/{total_count}" if total_count else "unknown"

        if total_count > 0 and laps_count < total_count * 0.5:
            status, severity = STATUS_WARN, SEVERITY_MEDIUM
        else:
            status, severity = STATUS_PASS, SEVERITY_INFO

        self.add_finding(
            test_id="MISC-001",
            test_name="LAPS Deployment",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=f"LAPS schema is deployed: {', '.join(laps_type)}.",
            observation=f"LAPS coverage: {coverage} non-DC computers have LAPS password expiration set.",
            remediation="Ensure LAPS is deployed to all workstations and member servers.",
            details={"laps_type": laps_type, "coverage": coverage, "laps_count": laps_count, "total_computers": total_count},
        )

    def _check_machine_account_quota(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domainDNS)",
            attributes=["ms-DS-MachineAccountQuota"],
            search_scope="BASE",
        )

        maq = 10
        if entries:
            raw = entries[0]["ms-DS-MachineAccountQuota"].value if "ms-DS-MachineAccountQuota" in entries[0].entry_attributes else None
            if raw is not None:
                try:
                    maq = int(str(raw))
                except (ValueError, TypeError):
                    pass

        if maq >= 10:
            status, severity = STATUS_FAIL, SEVERITY_HIGH
        elif maq > 0:
            status, severity = STATUS_WARN, SEVERITY_MEDIUM
        else:
            status, severity = STATUS_PASS, SEVERITY_INFO

        self.add_finding(
            test_id="MISC-002",
            test_name="MachineAccountQuota",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=(
                "ms-DS-MachineAccountQuota controls how many computer accounts a user can "
                "create. The default value of 10 enables attacks like noPac and RBCD."
            ),
            observation=f"MachineAccountQuota = {maq}.",
            remediation="Set ms-DS-MachineAccountQuota to 0.",
            details={"machineAccountQuota": maq},
        )

    def _check_functional_level(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domainDNS)",
            attributes=["msDS-Behavior-Version"],
            search_scope="BASE",
        )

        level_map = {
            0: "Windows 2000",
            1: "Windows Server 2003 Interim",
            2: "Windows Server 2003",
            3: "Windows Server 2008",
            4: "Windows Server 2008 R2",
            5: "Windows Server 2012",
            6: "Windows Server 2012 R2",
            7: "Windows Server 2016",
            8: "Windows Server 2019",
            9: "Windows Server 2022",
            10: "Windows Server 2025",
        }

        level = -1
        if entries:
            raw = entries[0]["msDS-Behavior-Version"].value if "msDS-Behavior-Version" in entries[0].entry_attributes else None
            if raw is not None:
                try:
                    level = int(str(raw))
                except (ValueError, TypeError):
                    pass

        level_name = level_map.get(level, f"Unknown ({level})")

        if level < 7:
            status, severity = STATUS_WARN, SEVERITY_MEDIUM
        else:
            status, severity = STATUS_PASS, SEVERITY_INFO

        self.add_finding(
            test_id="MISC-003",
            test_name="Domain Functional Level",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description="Domain functional level determines available AD features and security controls.",
            observation=f"Domain Functional Level: {level_name} (value: {level}).",
            remediation="Raise the functional level to Windows Server 2016 or higher to enable latest security features." if level < 7 else "",
            details={"functionalLevel": level, "name": level_name},
        )

    def _check_recycle_bin(self):
        config_dn = self.domain_info.get("config_dn", f"CN=Configuration,{self.get_domain_dn()}")
        rb_dn = f"CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}"

        entries = self.ldap_search(
            rb_dn,
            "(objectClass=msDS-OptionalFeature)",
            attributes=["msDS-EnabledFeatureBL"],
            search_scope="BASE",
        )

        if entries and hasattr(entries[0], "msDS-EnabledFeatureBL"):
            enabled_bl = entries[0]["msDS-EnabledFeatureBL"].values if entries[0]["msDS-EnabledFeatureBL"] else []
            if enabled_bl:
                self.add_finding(
                    test_id="MISC-004",
                    test_name="AD Recycle Bin",
                    category=self.MODULE_NAME,
                    status=STATUS_PASS,
                    severity=SEVERITY_INFO,
                    description="AD Recycle Bin is enabled, allowing recovery of deleted objects.",
                    observation=f"Recycle Bin enabled for {len(enabled_bl)} naming context(s).",
                )
                return

        self.add_finding(
            test_id="MISC-004",
            test_name="AD Recycle Bin",
            category=self.MODULE_NAME,
            status=STATUS_WARN,
            severity=SEVERITY_LOW,
            description="AD Recycle Bin does not appear to be enabled.",
            observation="msDS-EnabledFeatureBL is empty or not present.",
            remediation="Enable AD Recycle Bin: Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <forest>",
        )
