from modules.base import BaseModule, Finding
from config import *


FUNCTIONAL_LEVELS = {
    "0": "2000",
    "1": "2003 Interim",
    "2": "2003",
    "3": "2008",
    "4": "2008 R2",
    "5": "2012",
    "6": "2012 R2",
    "7": "2016",
}

TRUST_DIRECTION = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}

TRUST_TYPE = {
    1: "Downlevel (Windows NT)",
    2: "Uplevel (Active Directory)",
    3: "MIT (Kerberos realm)",
    4: "DCE (Distributed Computing Environment)",
}

TRUST_ATTRIBUTES = {
    0x00000001: "Non-Transitive",
    0x00000002: "Uplevel Only",
    0x00000004: "SID Filtering Quarantined",
    0x00000008: "Forest Transitive",
    0x00000010: "Cross-Organization",
    0x00000020: "Within Forest",
    0x00000040: "Treat as External",
    0x00000080: "Uses RC4 Encryption",
    0x00000200: "No TGT Delegation",
    0x00000400: "PIM Trust",
}


class DomainReconModule(BaseModule):
    MODULE_NAME = "Domain Recon"
    MODULE_DESCRIPTION = "Enumerates domain information, controllers, trusts, sites and functional levels"

    def execute(self):
        self._domain_info()
        self._enumerate_dcs()
        self._trust_relationships()
        self._domain_functional_level()
        self._forest_functional_level()
        self._sites_and_subnets()

    def _resolve_functional_level(self, raw):
        val = str(raw)
        return FUNCTIONAL_LEVELS.get(val, f"Unknown ({val})")

    def _domain_info(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domain)",
            attributes=[
                "dc", "distinguishedName", "msDS-Behavior-Version",
                "objectSid", "whenCreated", "ms-DS-MachineAccountQuota",
            ],
            search_scope="BASE",
        )
        info_lines = [
            f"Domain DN: {self.get_domain_dn()}",
            f"Domain Name: {self.get_domain_name()}",
        ]
        if entries:
            e = entries[0]
            fl = getattr(e, "msDS-Behavior-Version", None)
            if fl is not None:
                info_lines.append(f"Functional Level: {self._resolve_functional_level(fl.value)}")
            created = getattr(e, "whenCreated", None)
            if created is not None:
                info_lines.append(f"Created: {created.value}")

        config_dn = f"CN=Partitions,CN=Configuration,{self.get_domain_dn()}"
        parts = self.ldap_search(
            config_dn,
            f"(&(objectClass=crossRef)(nCName={self.get_domain_dn()}))",
            attributes=["dnsRoot", "nETBIOSName", "nCName"],
        )
        if parts:
            p = parts[0]
            dns_root = getattr(p, "dnsRoot", None)
            netbios = getattr(p, "nETBIOSName", None)
            if dns_root:
                info_lines.append(f"DNS Root: {dns_root.value}")
            if netbios:
                info_lines.append(f"NetBIOS Name: {netbios.value}")

        forest_dn = f"CN=Partitions,CN=Configuration,{self.get_domain_dn()}"
        forest_entries = self.ldap_search(
            forest_dn,
            "(&(objectClass=crossRef)(systemFlags=3))",
            attributes=["dnsRoot"],
        )
        if forest_entries:
            info_lines.append(f"Forest Root: {forest_entries[0].dnsRoot.value}")

        self.add_finding(
            test_id="DOM-001",
            test_name="Domain Information",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Basic domain information gathered via LDAP.",
            observation="\n".join(info_lines),
        )

    def _enumerate_dcs(self):
        entries = self.ldap_search(
            f"OU=Domain Controllers,{self.get_domain_dn()}",
            "(objectClass=computer)",
            attributes=["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion", "whenCreated"],
        )
        dc_list = []
        for e in entries:
            name = str(getattr(e, "cn", "?"))
            dns = str(getattr(e, "dNSHostName", "N/A"))
            os_name = str(getattr(e, "operatingSystem", "N/A"))
            dc_list.append(f"{name} | {dns} | {os_name}")

        self.add_finding(
            test_id="DOM-002",
            test_name="Domain Controllers",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Enumerated all domain controllers.",
            observation=f"Found {len(dc_list)} domain controller(s).",
            affected_objects=dc_list,
        )

    def _trust_relationships(self):
        entries = self.ldap_search(
            f"CN=System,{self.get_domain_dn()}",
            "(objectClass=trustedDomain)",
            attributes=[
                "cn", "trustDirection", "trustType", "trustAttributes",
                "trustPartner", "whenCreated", "flatName",
            ],
        )
        if not entries:
            self.add_finding(
                test_id="DOM-003",
                test_name="Trust Relationships",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No domain trust relationships found.",
                observation="The domain has no configured trusts.",
            )
            return

        trust_details = []
        has_external = False
        for e in entries:
            partner = str(getattr(e, "trustPartner", "?"))
            direction_raw = int(getattr(e, "trustDirection", 0))
            type_raw = int(getattr(e, "trustType", 0))
            attrs_raw = int(getattr(e, "trustAttributes", 0))
            direction = TRUST_DIRECTION.get(direction_raw, f"Unknown({direction_raw})")
            ttype = TRUST_TYPE.get(type_raw, f"Unknown({type_raw})")

            attr_flags = []
            for bit, label in TRUST_ATTRIBUTES.items():
                if attrs_raw & bit:
                    attr_flags.append(label)

            is_forest = attrs_raw & 0x00000008
            is_external = not (attrs_raw & 0x00000020)
            if is_external or is_forest:
                has_external = True

            trust_details.append(
                f"{partner} | Direction: {direction} | Type: {ttype} | "
                f"Attributes: {', '.join(attr_flags) if attr_flags else 'None'}"
            )

        status = STATUS_WARN if has_external else STATUS_INFO
        severity = SEVERITY_MEDIUM if has_external else SEVERITY_INFO
        obs = f"Found {len(entries)} trust(s)."
        if has_external:
            obs += " External/forest trusts detected — review for lateral movement risk."

        self.add_finding(
            test_id="DOM-003",
            test_name="Trust Relationships",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description="Trust relationships expose the domain to cross-boundary attacks if misconfigured.",
            observation=obs,
            affected_objects=trust_details,
            remediation="Review trust configurations. Ensure SID filtering is enabled on external trusts. "
                        "Remove unnecessary trusts.",
        )

    def _domain_functional_level(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domain)",
            attributes=["msDS-Behavior-Version"],
            search_scope="BASE",
        )
        if not entries:
            return
        raw = getattr(entries[0], "msDS-Behavior-Version", None)
        if raw is None:
            return
        level = int(raw.value)
        level_name = self._resolve_functional_level(raw.value)
        below_2016 = level < 7

        self.add_finding(
            test_id="DOM-004",
            test_name="Domain Functional Level",
            category=self.MODULE_NAME,
            status=STATUS_WARN if below_2016 else STATUS_PASS,
            severity=SEVERITY_MEDIUM if below_2016 else SEVERITY_INFO,
            description="Lower functional levels lack modern security features like Credential Guard support.",
            observation=f"Domain functional level: {level_name}.",
            remediation="Raise functional level to Windows Server 2016 or higher to enable "
                        "Privileged Access Management and other modern protections."
                        if below_2016 else "",
        )

    def _forest_functional_level(self):
        config_dn = f"CN=Partitions,CN=Configuration,{self.get_domain_dn()}"
        entries = self.ldap_search(
            config_dn,
            "(objectClass=crossRefContainer)",
            attributes=["msDS-Behavior-Version"],
            search_scope="BASE",
        )
        if not entries:
            return
        raw = getattr(entries[0], "msDS-Behavior-Version", None)
        if raw is None:
            return
        level = int(raw.value)
        level_name = self._resolve_functional_level(raw.value)
        below_2016 = level < 7

        self.add_finding(
            test_id="DOM-005",
            test_name="Forest Functional Level",
            category=self.MODULE_NAME,
            status=STATUS_WARN if below_2016 else STATUS_PASS,
            severity=SEVERITY_MEDIUM if below_2016 else SEVERITY_INFO,
            description="Forest functional level determines available AD features across the forest.",
            observation=f"Forest functional level: {level_name}.",
            remediation="Raise forest functional level to Windows Server 2016 or higher."
                        if below_2016 else "",
        )

    def _sites_and_subnets(self):
        sites_dn = f"CN=Sites,CN=Configuration,{self.get_domain_dn()}"
        sites = self.ldap_search(
            sites_dn,
            "(objectClass=site)",
            attributes=["cn", "description", "whenCreated"],
        )
        site_names = [str(getattr(s, "cn", "?")) for s in sites]

        subnets_dn = f"CN=Subnets,CN=Sites,CN=Configuration,{self.get_domain_dn()}"
        subnets = self.ldap_search(
            subnets_dn,
            "(objectClass=subnet)",
            attributes=["cn", "siteObject", "description"],
        )
        subnet_details = []
        for s in subnets:
            name = str(getattr(s, "cn", "?"))
            site_obj = str(getattr(s, "siteObject", "N/A"))
            site_short = site_obj.split(",")[0].replace("CN=", "") if "CN=" in site_obj else site_obj
            subnet_details.append(f"{name} -> {site_short}")

        self.add_finding(
            test_id="DOM-006",
            test_name="Sites and Subnets",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Active Directory sites and subnets define replication topology and client affinity.",
            observation=f"Found {len(site_names)} site(s) and {len(subnet_details)} subnet(s).",
            affected_objects=site_names + subnet_details,
        )
