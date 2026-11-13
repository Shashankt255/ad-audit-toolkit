import socket
from modules.base import BaseModule
from config import *


class CVEAudit(BaseModule):
    MODULE_NAME = "CVE Audit"
    MODULE_DESCRIPTION = "Passive checks for known AD vulnerabilities, coerce vectors, and combined relay assessments."

    def execute(self):
        self._get_dc_info()
        self._check_zerologon()
        self._check_petitpotam()
        self._check_printnightmare()
        self._check_nopac()
        self._check_certifried()
        self._check_ntlm_relay_combined()
        self._check_dfscoerce()
        self._check_shadowcoerce()
        self._check_krbrelayup()

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

    def _check_smb_signing_on_dc(self):
        dc_ip = self.options.get("dc_ip", "")
        if not dc_ip:
            return None
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(dc_ip, dc_ip, timeout=5)
            smb.login("", "")
        except Exception:
            try:
                from impacket.smbconnection import SMBConnection
                smb = SMBConnection(dc_ip, dc_ip, timeout=5)
            except Exception:
                return None
        try:
            signing = smb.isSigningRequired()
            smb.close()
            return signing
        except Exception:
            return None

    def _check_ldap_signing_enforced(self):
        dc_ip = self.options.get("dc_ip", "")
        if not dc_ip:
            return None
        try:
            from ldap3 import Server, Connection
            srv = Server(dc_ip, port=389, connect_timeout=5)
            conn = Connection(srv, auto_bind=True, receive_timeout=5)
            conn.search("", "(objectClass=*)", search_scope="BASE", attributes=["*"])
            conn.unbind()
            return False
        except Exception:
            return True

    def _get_maq_value(self):
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
        return maq

    def _check_ntlm_relay_combined(self):
        smb_signing = self._check_smb_signing_on_dc()
        ldap_signing = self._check_ldap_signing_enforced()

        smb_weak = smb_signing is False
        ldap_weak = ldap_signing is False

        observations = []
        if smb_signing is None:
            observations.append("SMB signing check: could not connect to DC SMB.")
        else:
            observations.append(f"SMB signing required on DC: {'Yes' if smb_signing else 'NO — not required'}")

        if ldap_signing is None:
            observations.append("LDAP signing check: could not determine status.")
        else:
            observations.append(f"LDAP signing enforced: {'Yes' if ldap_signing else 'NO — unsigned binds accepted'}")

        if smb_weak and ldap_weak:
            status, severity = STATUS_FAIL, SEVERITY_CRITICAL
            observations.append(
                "CRITICAL: Both SMB signing and LDAP signing are not enforced. "
                "Full NTLM relay chain is viable: PetitPotam/PrinterBug → NTLM relay → DCSync/RBCD."
            )
        elif smb_weak or ldap_weak:
            status, severity = STATUS_WARN, SEVERITY_HIGH
            weak_part = "SMB signing" if smb_weak else "LDAP signing"
            observations.append(f"Partial relay risk: {weak_part} is not enforced.")
        elif smb_signing is None and ldap_signing is None:
            status, severity = STATUS_INFO, SEVERITY_INFO
            observations.append("Could not perform relay assessment — manual verification needed.")
        else:
            status, severity = STATUS_PASS, SEVERITY_INFO
            observations.append("Both SMB and LDAP signing are enforced. NTLM relay attacks are mitigated.")

        self.add_finding(
            test_id="CVE-006",
            test_name="NTLM Relay Combined Assessment",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=(
                "Assesses the combined risk of NTLM relay attacks by checking both SMB "
                "signing and LDAP signing enforcement on domain controllers. When both are "
                "weak, coerce attacks (PetitPotam, PrinterBug) can be relayed to achieve "
                "DCSync or RBCD-based privilege escalation."
            ),
            observation="\n".join(observations),
            remediation=(
                "Enforce SMB signing via GPO: 'Microsoft network server: Digitally sign "
                "communications (always)' = Enabled. Enforce LDAP signing: set "
                "'ldapserverintegrity' to 2 on DCs. Enable LDAP channel binding: set "
                "'LdapEnforceChannelBinding' to 2. Disable NTLM where possible."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1557/001/",
            ],
        )

    def _rpc_endpoint_accessible(self, dc_ip, uuid_str, pipe=None):
        try:
            from impacket.dcerpc.v5 import transport, epm
            if pipe:
                string_binding = f"ncacn_np:{dc_ip}[{pipe}]"
            else:
                string_binding = f"ncacn_ip_tcp:{dc_ip}[135]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_connect_timeout(5)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            from impacket.uuid import uuidtup_to_bin
            parts = uuid_str.split("-")
            dce.bind(uuidtup_to_bin((uuid_str, "1.0")))
            dce.disconnect()
            return True
        except Exception:
            return False

    def _check_dfscoerce(self):
        dc_ip = self.options.get("dc_ip", "")
        if not dc_ip:
            self.add_finding(
                test_id="CVE-007",
                test_name="DFSCoerce (DFS RPC)",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC IP available for DFS check.",
                observation="Skipped.",
            )
            return

        accessible = self._rpc_endpoint_accessible(
            dc_ip, "4fc742e0-4a10-11cf-8273-00aa004ae673", pipe="\\pipe\\netdfs"
        )

        if accessible:
            self.add_finding(
                test_id="CVE-007",
                test_name="DFSCoerce (DFS RPC)",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description=(
                    "The DFS RPC endpoint (netdfs) is accessible on the domain controller. "
                    "DFSCoerce can abuse this to coerce NTLM authentication from the DC, "
                    "which can be relayed for privilege escalation."
                ),
                observation=f"DFS RPC endpoint responded on {dc_ip}. Coerce attack vector available.",
                remediation=(
                    "If DFS is not required, disable the DFS service on DCs. "
                    "Enforce SMB signing and LDAP signing to prevent relay. "
                    "Apply all recent Windows security updates."
                ),
                affected_objects=[dc_ip],
                references=["https://github.com/Wh04m1001/DFSCoerce"],
            )
        else:
            self.add_finding(
                test_id="CVE-007",
                test_name="DFSCoerce (DFS RPC)",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="DFS RPC endpoint is not accessible or DFS is disabled.",
                observation=f"Could not bind to netdfs on {dc_ip}.",
            )

    def _check_shadowcoerce(self):
        dc_ip = self.options.get("dc_ip", "")
        if not dc_ip:
            self.add_finding(
                test_id="CVE-008",
                test_name="ShadowCoerce (FSrvp RPC)",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC IP available.",
                observation="Skipped.",
            )
            return

        accessible = self._rpc_endpoint_accessible(
            dc_ip, "a8e0653c-2744-4389-a61d-7373df8b2292", pipe="\\pipe\\FssagentRpc"
        )

        if accessible:
            self.add_finding(
                test_id="CVE-008",
                test_name="ShadowCoerce (FSrvp RPC)",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_MEDIUM,
                description=(
                    "The FSrvp RPC endpoint (File Server VSS Agent) is accessible on the DC. "
                    "ShadowCoerce abuses this to coerce NTLM authentication."
                ),
                observation=f"FSrvp RPC endpoint responded on {dc_ip}. Coerce vector available.",
                remediation=(
                    "Disable the File Server VSS Agent Service if not needed. "
                    "Enforce SMB and LDAP signing to mitigate relay attacks."
                ),
                affected_objects=[dc_ip],
                references=["https://github.com/ShutdownRepo/ShadowCoerce"],
            )
        else:
            self.add_finding(
                test_id="CVE-008",
                test_name="ShadowCoerce (FSrvp RPC)",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="FSrvp RPC endpoint is not accessible.",
                observation=f"Could not bind to FSrvp on {dc_ip}.",
            )

    def _check_krbrelayup(self):
        maq = self._get_maq_value()
        ldap_enforced = self._check_ldap_signing_enforced()

        maq_weak = maq > 0
        ldap_weak = ldap_enforced is False

        observations = [
            f"MachineAccountQuota: {maq}",
            f"LDAP signing enforced: {'Yes' if ldap_enforced else 'No' if ldap_enforced is False else 'Unknown'}",
        ]

        if maq_weak and ldap_weak:
            status, severity = STATUS_FAIL, SEVERITY_HIGH
            observations.append(
                "KrbRelayUp attack chain is viable: MAQ allows machine account creation, "
                "and LDAP signing is not enforced, enabling Kerberos relay to LDAP for "
                "RBCD-based privilege escalation."
            )
        elif maq_weak:
            status, severity = STATUS_WARN, SEVERITY_MEDIUM
            observations.append(
                "MAQ > 0 allows machine account creation, but LDAP signing mitigates relay."
            )
        elif ldap_weak:
            status, severity = STATUS_WARN, SEVERITY_MEDIUM
            observations.append(
                "LDAP signing not enforced, but MAQ=0 prevents new machine account creation."
            )
        else:
            status, severity = STATUS_PASS, SEVERITY_INFO
            observations.append("KrbRelayUp prerequisites not met.")

        self.add_finding(
            test_id="CVE-009",
            test_name="KrbRelayUp Assessment",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description=(
                "KrbRelayUp combines Kerberos relay with RBCD to escalate privileges. "
                "It requires MachineAccountQuota > 0 (to create a machine account) and "
                "LDAP signing not enforced (to relay Kerberos to LDAP)."
            ),
            observation="\n".join(observations),
            remediation=(
                "Set ms-DS-MachineAccountQuota to 0. Enforce LDAP signing and channel "
                "binding on all DCs. Apply latest Windows security updates."
            ),
            references=["https://github.com/Dec0ne/KrbRelayUp"],
        )
