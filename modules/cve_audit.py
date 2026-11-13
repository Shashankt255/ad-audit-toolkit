from modules.base import BaseModule
from config import *


class CVEAudit(BaseModule):
    MODULE_NAME = "CVE Audit"
    MODULE_DESCRIPTION = "Passive checks for known AD vulnerabilities (ZeroLogon, PetitPotam, PrintNightmare, noPac, Certifried)."

    def execute(self):
        self._get_dc_info()
        self._check_zerologon()
        self._check_petitpotam()
        self._check_printnightmare()
        self._check_nopac()
        self._check_certifried()

    def _get_dc_info(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectCategory=computer)(primaryGroupID=516))",
            attributes=["sAMAccountName", "operatingSystem", "operatingSystemVersion", "dNSHostName"],
        )
        self._dcs = []
        for entry in entries:
            self._dcs.append({
                "name": str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "N/A",
                "os": str(entry.operatingSystem) if hasattr(entry, "operatingSystem") else "Unknown",
                "version": str(entry.operatingSystemVersion) if hasattr(entry, "operatingSystemVersion") else "Unknown",
                "dns": str(entry.dNSHostName) if hasattr(entry, "dNSHostName") else "N/A",
            })

    def _check_zerologon(self):
        if not self._dcs:
            self.add_finding(
                test_id="CVE-001",
                test_name="ZeroLogon (CVE-2020-1472)",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC information available.",
                observation="Cannot assess ZeroLogon exposure.",
            )
            return

        self.add_finding(
            test_id="CVE-001",
            test_name="ZeroLogon (CVE-2020-1472)",
            category=self.MODULE_NAME,
            status=STATUS_WARN,
            severity=SEVERITY_CRITICAL,
            description=(
                "ZeroLogon (CVE-2020-1472) allows unauthenticated domain compromise by "
                "exploiting a flaw in the Netlogon protocol. Verify all DCs are patched "
                "(August 2020+ updates)."
            ),
            observation=(
                f"Found {len(self._dcs)} DC(s). OS versions: "
                + ", ".join(f"{d['name']} ({d['os']})" for d in self._dcs[:5])
                + ". Verify patch status manually."
            ),
            remediation=(
                "Apply Microsoft security update KB4571702 (August 2020) or later. "
                "Enable FullSecureChannelProtection registry key. "
                "Monitor Event ID 5829 for vulnerable connections."
            ),
            affected_objects=[d["name"] for d in self._dcs],
            details={"dcs": self._dcs},
            cve="CVE-2020-1472",
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"],
        )

    def _check_petitpotam(self):
        if not self._dcs:
            self.add_finding(
                test_id="CVE-002",
                test_name="PetitPotam (CVE-2021-36942)",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC information available.",
                observation="Cannot assess PetitPotam exposure.",
            )
            return

        self.add_finding(
            test_id="CVE-002",
            test_name="PetitPotam (CVE-2021-36942)",
            category=self.MODULE_NAME,
            status=STATUS_WARN,
            severity=SEVERITY_HIGH,
            description=(
                "PetitPotam abuses EFSRPC to coerce authentication from DCs. Combined "
                "with NTLM relay to AD CS, this can lead to domain compromise."
            ),
            observation=(
                f"{len(self._dcs)} DC(s) identified. EFS RPC is enabled by default. "
                "Verify August 2021+ patches are applied and consider disabling EFS if unused."
            ),
            remediation=(
                "Apply KB5005413 (August 2021) or later. Disable NTLM where possible. "
                "Enable Extended Protection for Authentication on AD CS web endpoints. "
                "Consider disabling EFS RPC if not needed."
            ),
            affected_objects=[d["name"] for d in self._dcs],
            cve="CVE-2021-36942",
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942"],
        )

    def _check_printnightmare(self):
        if not self._dcs:
            self.add_finding(
                test_id="CVE-003",
                test_name="PrintNightmare (CVE-2021-34527)",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC information available.",
                observation="Cannot assess PrintNightmare exposure.",
            )
            return

        self.add_finding(
            test_id="CVE-003",
            test_name="PrintNightmare (CVE-2021-34527)",
            category=self.MODULE_NAME,
            status=STATUS_WARN,
            severity=SEVERITY_CRITICAL,
            description=(
                "PrintNightmare allows remote code execution via the Print Spooler service. "
                "The Spooler service is enabled by default on all Windows systems including DCs."
            ),
            observation=(
                f"{len(self._dcs)} DC(s) identified. The Print Spooler service is typically "
                "enabled by default. Verify patches and consider disabling the Spooler on DCs."
            ),
            remediation=(
                "Apply KB5004945 (July 2021) or later. Disable the Print Spooler service "
                "on DCs: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled. "
                "Set RestrictDriverInstallationToAdministrators to 1."
            ),
            affected_objects=[d["name"] for d in self._dcs],
            cve="CVE-2021-34527",
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"],
        )

    def _check_nopac(self):
        maq_entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domainDNS)",
            attributes=["ms-DS-MachineAccountQuota"],
            search_scope="BASE",
        )

        maq = 10
        if maq_entries:
            raw = maq_entries[0]["ms-DS-MachineAccountQuota"].value if "ms-DS-MachineAccountQuota" in maq_entries[0].entry_attributes else None
            if raw is not None:
                try:
                    maq = int(str(raw))
                except (ValueError, TypeError):
                    pass

        if maq > 0:
            status, severity = STATUS_WARN, SEVERITY_HIGH
            obs = (
                f"MachineAccountQuota = {maq}. Any domain user can add up to {maq} "
                f"computer(s), enabling the noPac attack chain if DCs are unpatched."
            )
        else:
            status, severity = STATUS_PASS, SEVERITY_INFO
            obs = "MachineAccountQuota = 0. Users cannot add machine accounts."

        self.add_finding(
            test_id="CVE-004",
            test_name="noPac / sAMAccountName Spoofing (CVE-2021-42278/42287)",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=(
                "noPac exploits sAMAccountName spoofing to impersonate DCs and obtain "
                "admin-level TGTs. Requires the ability to add machine accounts "
                "(MachineAccountQuota > 0) and unpatched DCs."
            ),
            observation=obs,
            remediation=(
                "Apply November 2021 patches (KB5007205/KB5007206). Set "
                "ms-DS-MachineAccountQuota to 0 to prevent regular users from "
                "adding machine accounts."
            ),
            details={"machineAccountQuota": maq},
            cve="CVE-2021-42278",
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278"],
        )

    def _check_certifried(self):
        config_dn = self.domain_info.get("config_dn", f"CN=Configuration,{self.get_domain_dn()}")
        ca_entries = self.ldap_search(
            f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}",
            "(objectClass=pKIEnrollmentService)",
            attributes=["cn"],
        )

        adcs_deployed = bool(ca_entries)

        if adcs_deployed:
            self.add_finding(
                test_id="CVE-005",
                test_name="Certifried (CVE-2022-26923)",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description=(
                    "Certifried allows a low-privileged user who can enroll machine "
                    "certificates to escalate to Domain Admin by spoofing a DC's identity."
                ),
                observation=(
                    f"AD CS is deployed ({len(ca_entries)} CA(s) found). "
                    f"Verify May 2022 patches (KB5014754) are applied on all DCs."
                ),
                remediation=(
                    "Apply KB5014754 (May 2022). Review certificate templates that allow "
                    "machine enrollment with subject name supplied by enrollee."
                ),
                affected_objects=[str(ca.cn) if hasattr(ca, "cn") else "N/A" for ca in ca_entries],
                cve="CVE-2022-26923",
                references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923"],
            )
        else:
            self.add_finding(
                test_id="CVE-005",
                test_name="Certifried (CVE-2022-26923)",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="AD CS is not deployed; Certifried is not applicable.",
                observation="No Enrollment Services found in the domain.",
            )
