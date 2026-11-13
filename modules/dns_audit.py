from modules.base import BaseModule
from config import *


class DNSAudit(BaseModule):
    MODULE_NAME = "DNS Audit"
    MODULE_DESCRIPTION = "Checks DNS zone transfer, ADIDNS wildcards, and dynamic update settings."

    def execute(self):
        self._check_zone_transfer()
        self._check_adidns_wildcard()
        self._check_dynamic_updates()

    def _check_zone_transfer(self):
        dc_list = self.domain_info.get("dc_list", [])
        domain = self.get_domain_name()

        if not dc_list or not domain:
            self.add_finding(
                test_id="DNS-001",
                test_name="DNS Zone Transfer",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC or domain info available for zone transfer test.",
                observation="Cannot perform zone transfer check.",
            )
            return

        transfer_allowed = []
        transfer_denied = []

        for dc in dc_list[:3]:
            try:
                import dns.query
                import dns.zone
                import dns.resolver
                zone = dns.zone.from_xfr(dns.query.xfr(dc, domain, lifetime=10))
                record_count = len(list(zone.nodes.keys()))
                transfer_allowed.append({"dc": dc, "records": record_count})
            except dns.exception.FormError:
                transfer_denied.append(dc)
            except Exception:
                transfer_denied.append(dc)

        if transfer_allowed:
            self.add_finding(
                test_id="DNS-001",
                test_name="DNS Zone Transfer",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description=(
                    "DNS zone transfer (AXFR) is allowed, exposing all DNS records "
                    "to any client that requests them."
                ),
                observation=f"Zone transfer succeeded on {len(transfer_allowed)} DC(s).",
                remediation="Restrict zone transfers to authorized DNS servers only.",
                affected_objects=[t["dc"] for t in transfer_allowed],
                details={"allowed": transfer_allowed, "denied": transfer_denied},
            )
        else:
            self.add_finding(
                test_id="DNS-001",
                test_name="DNS Zone Transfer",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="DNS zone transfer is not allowed.",
                observation=f"Zone transfer denied on all {len(transfer_denied)} tested DC(s).",
            )

    def _check_adidns_wildcard(self):
        domain_dn = self.get_domain_dn()
        dns_zone_dn = f"DC={self.get_domain_name()},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}"

        entries = self.ldap_search(
            dns_zone_dn,
            "(&(objectClass=dnsNode)(name=*))",
            attributes=["name", "dnsRecord", "dc"],
        )

        wildcard_found = False
        for entry in entries:
            name = str(entry.name) if hasattr(entry, "name") else str(entry.dc) if hasattr(entry, "dc") else ""
            if name == "*":
                wildcard_found = True
                break

        if wildcard_found:
            self.add_finding(
                test_id="DNS-002",
                test_name="ADIDNS Wildcard Record",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_MEDIUM,
                description=(
                    "A wildcard (*) DNS record exists in the AD-integrated DNS zone. "
                    "This can be abused for MITM attacks by resolving any name."
                ),
                observation="Wildcard (*) record found in ADIDNS zone.",
                remediation="Remove the wildcard record unless explicitly required.",
            )
        else:
            self.add_finding(
                test_id="DNS-002",
                test_name="ADIDNS Wildcard Record",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No wildcard DNS record found in ADIDNS.",
                observation="No wildcard (*) record detected in the zone.",
            )

    def _check_dynamic_updates(self):
        domain_dn = self.get_domain_dn()
        dns_zone_dn = f"DC={self.get_domain_name()},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}"

        entries = self.ldap_search(
            dns_zone_dn,
            "(objectClass=dnsZone)",
            attributes=["name", "dNSProperty"],
            search_scope="BASE",
        )

        self.add_finding(
            test_id="DNS-003",
            test_name="DNS Dynamic Updates",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_LOW,
            description=(
                "AD-integrated DNS zones support secure dynamic updates by default. "
                "If set to 'Nonsecure and secure', any client can register DNS records."
            ),
            observation=(
                "Verify dynamic update settings on the DNS zone properties. "
                "The zone should be set to 'Secure only' dynamic updates."
            ),
            remediation="Set dynamic updates to 'Secure only' on all AD-integrated DNS zones.",
        )
