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
        self._check_sid_history()
        self._check_exchange_integration()
        self._check_gmsa()
        self._check_azure_ad_connect()
        self._check_tombstone_lifetime()

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

    def _check_sid_history(self):
        PRIV_RID_SUFFIXES = ("-500", "-512", "-516", "-518", "-519")
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(sIDHistory=*)",
            attributes=["sAMAccountName", "sIDHistory", "objectClass"],
        )

        if not entries:
            self.add_finding(
                test_id="MISC-005",
                test_name="SID History Abuse",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="SID History allows a migrated account to retain access to resources in a source domain. "
                            "Attackers abuse it for cross-domain privilege escalation and persistence.",
                observation="No objects with SID History found.",
            )
            return

        priv_sid_objects = []
        all_sid_objects = []
        for entry in entries:
            sam = str(getattr(entry, "sAMAccountName", "?"))
            sid_raw = getattr(entry, "sIDHistory", None)
            sids = []
            if sid_raw:
                if hasattr(sid_raw, "values"):
                    sids = [str(s) for s in sid_raw.values]
                elif sid_raw.value:
                    sids = [str(sid_raw.value)]

            all_sid_objects.append(f"{sam} (SIDs: {', '.join(sids[:3])}{'...' if len(sids) > 3 else ''})")

            for sid in sids:
                if any(sid.endswith(suffix) for suffix in PRIV_RID_SUFFIXES):
                    priv_sid_objects.append(f"{sam} has privileged SID: {sid}")

        if priv_sid_objects:
            self.add_finding(
                test_id="MISC-005",
                test_name="SID History Abuse",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Objects with SID History containing privileged SIDs (Administrator, Domain Admins, "
                            "Enterprise Admins, etc.) can escalate privileges across trust boundaries.",
                observation=f"{len(priv_sid_objects)} object(s) have SID History with privileged SIDs.",
                affected_objects=priv_sid_objects,
                remediation="Remove SID History from objects unless actively migrating. Use "
                            "Get-ADUser -Filter {SIDHistory -like '*'} to enumerate and "
                            "Set-ADUser -Remove @{SIDHistory='<SID>'} to clean up.",
                references=["https://attack.mitre.org/techniques/T1134/005/"],
            )
        else:
            self.add_finding(
                test_id="MISC-005",
                test_name="SID History Abuse",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description="Objects with SID History retain access to the source domain. This is a lateral "
                            "movement vector even without privileged SIDs.",
                observation=f"{len(all_sid_objects)} object(s) have SID History entries (none privileged).",
                affected_objects=all_sid_objects[:50],
                remediation="Remove SID History entries that are no longer needed after migration is complete.",
                references=["https://attack.mitre.org/techniques/T1134/005/"],
            )

    def _check_exchange_integration(self):
        exchange_groups_info = {}
        for group_name in ["Exchange Windows Permissions", "Exchange Trusted Subsystem", "Organization Management"]:
            results = self.ldap_search(
                self.get_domain_dn(),
                f"(&(objectClass=group)(cn={group_name}))",
                attributes=["cn", "member", "distinguishedName"],
            )
            if results:
                members = []
                raw = getattr(results[0], "member", None)
                if raw:
                    if hasattr(raw, "values"):
                        members = [str(m).split(",")[0].replace("CN=", "") for m in raw.values]
                    elif raw.value:
                        members = [str(raw.value).split(",")[0].replace("CN=", "")]
                exchange_groups_info[group_name] = members

        config_dn = self.domain_info.get("config_dn", f"CN=Configuration,{self.get_domain_dn()}")
        exchange_servers = self.ldap_search(
            config_dn,
            "(objectClass=msExchExchangeServer)",
            attributes=["cn"],
        )

        if not exchange_groups_info and not exchange_servers:
            self.add_finding(
                test_id="MISC-006",
                test_name="Exchange Integration Security",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Microsoft Exchange integration with AD introduces additional attack surface, "
                            "particularly the Exchange Windows Permissions group which has WriteDACL on the domain root.",
                observation="No Exchange groups or servers found. Exchange does not appear to be integrated.",
            )
            return

        ewp_members = exchange_groups_info.get("Exchange Windows Permissions", [])
        ets_members = exchange_groups_info.get("Exchange Trusted Subsystem", [])
        om_members = exchange_groups_info.get("Organization Management", [])
        server_count = len(exchange_servers) if exchange_servers else 0

        affected = []
        if ewp_members:
            affected.append(f"Exchange Windows Permissions: {len(ewp_members)} member(s) [{', '.join(ewp_members[:5])}]")
        if ets_members:
            affected.append(f"Exchange Trusted Subsystem: {len(ets_members)} member(s) [{', '.join(ets_members[:5])}]")
        if om_members:
            affected.append(f"Organization Management: {len(om_members)} member(s) [{', '.join(om_members[:5])}]")
        if server_count:
            affected.append(f"Exchange Servers: {server_count}")

        if ewp_members:
            self.add_finding(
                test_id="MISC-006",
                test_name="Exchange Integration Security",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Exchange Windows Permissions group has WriteDACL on the domain root by default. "
                            "Any member can grant themselves DCSync rights and dump all password hashes.",
                observation=f"Exchange Windows Permissions has {len(ewp_members)} member(s). "
                            f"This is a direct path to domain compromise via WriteDACL → DCSync.",
                affected_objects=affected,
                remediation="Remove unnecessary members from Exchange Windows Permissions. Remove the "
                            "WriteDACL permission from this group on the domain object. Consider the "
                            "Exchange Split Permissions model.",
                references=["https://attack.mitre.org/techniques/T1003/006/"],
            )
        else:
            self.add_finding(
                test_id="MISC-006",
                test_name="Exchange Integration Security",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description="Exchange is deployed in this environment. Exchange integration introduces additional "
                            "AD attack surface through privileged Exchange groups.",
                observation=f"Exchange detected ({server_count} server(s)). Review Exchange group memberships.",
                affected_objects=affected,
                remediation="Audit Exchange Windows Permissions, Exchange Trusted Subsystem, and Organization "
                            "Management group memberships. Apply least-privilege and consider Split Permissions.",
            )

    def _check_gmsa(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=msDS-GroupManagedServiceAccount)",
            attributes=["sAMAccountName", "servicePrincipalName",
                         "msDS-ManagedPasswordInterval", "msDS-GroupMSAMembership"],
        )

        if not entries:
            self.add_finding(
                test_id="MISC-007",
                test_name="Group Managed Service Accounts (gMSA)",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Group Managed Service Accounts (gMSA) provide automatic password management "
                            "for service accounts, reducing the risk of credential theft.",
                observation="No gMSA accounts found. Consider deploying gMSAs for service accounts.",
                remediation="Replace static service account passwords with gMSAs where supported.",
            )
            return

        gmsa_list = []
        readable_passwords = []
        for entry in entries:
            sam = str(getattr(entry, "sAMAccountName", "?"))
            spn_raw = getattr(entry, "servicePrincipalName", None)
            spns = []
            if spn_raw:
                if hasattr(spn_raw, "values"):
                    spns = [str(s) for s in spn_raw.values]
                elif spn_raw.value:
                    spns = [str(spn_raw.value)]

            interval_raw = getattr(entry, "msDS-ManagedPasswordInterval", None)
            interval = str(interval_raw.value) if interval_raw and interval_raw.value else "default(30)"

            gmsa_list.append(f"{sam} (rotate every {interval} days, SPNs: {', '.join(spns[:3]) or 'none'})")

            pwd_raw = getattr(entry, "msDS-ManagedPassword", None)
            if pwd_raw and pwd_raw.value:
                readable_passwords.append(sam)

        if readable_passwords:
            status, severity = STATUS_WARN, SEVERITY_MEDIUM
            obs = (f"Found {len(entries)} gMSA(s). Current user can read managed password "
                   f"for: {', '.join(readable_passwords)}. Verify this access is expected.")
        else:
            status, severity = STATUS_INFO, SEVERITY_INFO
            obs = f"Found {len(entries)} gMSA(s). Managed passwords not readable by current user."

        self.add_finding(
            test_id="MISC-007",
            test_name="Group Managed Service Accounts (gMSA)",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description="gMSAs provide automatic password rotation for service accounts. Verify that "
                        "only authorized principals can read the managed password.",
            observation=obs,
            affected_objects=gmsa_list,
            remediation="Review msDS-GroupMSAMembership on each gMSA to ensure only required "
                        "computer/service accounts can retrieve the password.",
        )

    def _check_azure_ad_connect(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(|(sAMAccountName=MSOL_*)(description=*Azure AD Connect*)"
            "(description=*Microsoft Azure AD Sync*)(sAMAccountName=AAD_*))",
            attributes=["sAMAccountName", "description", "whenCreated",
                         "adminCount", "memberOf"],
        )

        if not entries:
            self.add_finding(
                test_id="MISC-008",
                test_name="Azure AD Connect / Entra Connect",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Azure AD Connect (Entra Connect) sync accounts bridge on-premises AD "
                            "with cloud identity. These accounts typically have DCSync rights.",
                observation="No Azure AD Connect / Entra Connect sync accounts detected.",
            )
            return

        aad_accounts = []
        for entry in entries:
            sam = str(getattr(entry, "sAMAccountName", "?"))
            desc_raw = getattr(entry, "description", None)
            desc = ""
            if desc_raw:
                if hasattr(desc_raw, "values"):
                    desc = str(list(desc_raw.values)[0]) if desc_raw.values else ""
                elif desc_raw.value:
                    desc = str(desc_raw.value)
            created = str(getattr(entry, "whenCreated", "?"))
            admin_count = getattr(entry, "adminCount", None)
            has_admin = admin_count and str(admin_count.value) == "1"
            aad_accounts.append(
                f"{sam} (created: {created}, adminCount={1 if has_admin else 0}, desc: {desc[:60]})"
            )

        self.add_finding(
            test_id="MISC-008",
            test_name="Azure AD Connect / Entra Connect",
            category=self.MODULE_NAME,
            status=STATUS_WARN,
            severity=SEVERITY_HIGH,
            description="Azure AD Connect sync accounts (MSOL_*, AAD_*) typically have DCSync rights "
                        "and are high-value targets. Compromise of these accounts leads to full "
                        "on-premises and cloud domain compromise.",
            observation=f"Found {len(aad_accounts)} Azure AD Connect / Entra sync account(s).",
            affected_objects=aad_accounts,
            remediation="Verify sync accounts have minimal required permissions. Rotate passwords "
                        "regularly. Monitor for suspicious activity. Consider migrating to "
                        "Entra Cloud Sync which uses a less privileged gMSA.",
            references=["https://attack.mitre.org/techniques/T1003/006/"],
        )

    def _check_tombstone_lifetime(self):
        config_dn = self.domain_info.get("config_dn", f"CN=Configuration,{self.get_domain_dn()}")
        ds_dn = f"CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}"

        entries = self.ldap_search(
            ds_dn,
            "(objectClass=nTDSService)",
            attributes=["tombstoneLifetime"],
            search_scope="BASE",
        )

        tombstone = 180
        if entries:
            raw = getattr(entries[0], "tombstoneLifetime", None)
            if raw and raw.value:
                try:
                    tombstone = int(str(raw.value))
                except (ValueError, TypeError):
                    pass

        if tombstone < 60:
            status, severity = STATUS_WARN, SEVERITY_LOW
        else:
            status, severity = STATUS_INFO, SEVERITY_INFO

        self.add_finding(
            test_id="MISC-009",
            test_name="Tombstone Lifetime",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description="Tombstone lifetime determines how long deleted objects are retained before "
                        "permanent removal. Relevant for AD Recycle Bin and disaster recovery.",
            observation=f"Tombstone lifetime: {tombstone} days (default is 180).",
            remediation="Consider increasing tombstone lifetime to at least 180 days for "
                        "proper object recovery." if tombstone < 60 else "",
        )
