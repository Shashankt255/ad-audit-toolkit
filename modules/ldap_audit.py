import socket
from modules.base import BaseModule
from config import *


class LDAPAudit(BaseModule):
    MODULE_NAME = "LDAP Audit"
    MODULE_DESCRIPTION = "Checks LDAP signing, channel binding, anonymous access, and LDAPS configuration."

    def execute(self):
        self._check_ldap_signing()
        self._check_channel_binding()
        self._check_anonymous_bind()
        self._check_ldaps()
        self._check_null_base_dn()

    def _check_ldap_signing(self):
        conn_signed = False
        if self.ldap_conn.server and hasattr(self.ldap_conn.server, "ssl") and self.ldap_conn.server.ssl:
            conn_signed = True

        self.add_finding(
            test_id="LDAP-001",
            test_name="LDAP Signing",
            category=self.MODULE_NAME,
            status=STATUS_WARN if not conn_signed else STATUS_INFO,
            severity=SEVERITY_MEDIUM if not conn_signed else SEVERITY_INFO,
            description=(
                "LDAP signing prevents man-in-the-middle attacks on LDAP traffic. "
                "When not enforced, attackers can intercept and modify LDAP queries."
            ),
            observation=(
                f"Current connection {'uses SSL/TLS' if conn_signed else 'does not use SSL/TLS'}. "
                f"Verify LDAP signing enforcement via DC GPO: "
                f"'Domain controller: LDAP server signing requirements' should be 'Require signing'."
            ),
            remediation=(
                "Enable LDAP signing via Group Policy: Computer Configuration > Policies > "
                "Windows Settings > Security Settings > Local Policies > Security Options > "
                "'Domain controller: LDAP server signing requirements' = 'Require signing'."
            ),
        )

    def _check_channel_binding(self):
        self.add_finding(
            test_id="LDAP-002",
            test_name="LDAP Channel Binding",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_MEDIUM,
            description=(
                "LDAP channel binding tokens (CBT) prevent NTLM relay attacks against "
                "LDAP/LDAPS. This cannot be reliably determined via LDAP query alone."
            ),
            observation=(
                "Verify on each DC: Registry HKLM\\SYSTEM\\CurrentControlSet\\Services"
                "\\NTDS\\Parameters value 'LdapEnforceChannelBinding' should be 2 (Always)."
            ),
            remediation="Set LdapEnforceChannelBinding to 2 on all DCs.",
        )

    def _check_anonymous_bind(self):
        config_dn = self.domain_info.get("config_dn", f"CN=Configuration,{self.get_domain_dn()}")
        ds_dn = f"CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}"

        entries = self.ldap_search(
            ds_dn,
            "(objectClass=nTDSService)",
            attributes=["dsHeuristics"],
            search_scope="BASE",
        )

        if not entries:
            self.add_finding(
                test_id="LDAP-003",
                test_name="Anonymous LDAP Access",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Could not query dsHeuristics to check anonymous bind.",
                observation="LDAP query for nTDSService returned no results.",
            )
            return

        entry = entries[0]
        ds_heuristics = str(entry.dsHeuristics) if hasattr(entry, "dsHeuristics") else ""

        if ds_heuristics and len(ds_heuristics) >= 7 and ds_heuristics[6] == "2":
            self.add_finding(
                test_id="LDAP-003",
                test_name="Anonymous LDAP Access",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description=(
                    "Anonymous LDAP access is enabled (7th character of dsHeuristics = '2')."
                ),
                observation=f"dsHeuristics = '{ds_heuristics}'.",
                remediation="Set the 7th character of dsHeuristics to '0' to disable anonymous access.",
                details={"dsHeuristics": ds_heuristics},
            )
        else:
            self.add_finding(
                test_id="LDAP-003",
                test_name="Anonymous LDAP Access",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Anonymous LDAP access is not explicitly enabled.",
                observation=f"dsHeuristics = '{ds_heuristics or '(not set)'}'.",
            )

    def _check_ldaps(self):
        dc_list = self.domain_info.get("dc_list", [])
        if not dc_list:
            self.add_finding(
                test_id="LDAP-004",
                test_name="LDAPS Configuration",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC hostnames available to check LDAPS.",
                observation="Cannot test LDAPS port connectivity.",
            )
            return

        ldaps_available = []
        ldaps_unavailable = []

        for dc in dc_list[:5]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((dc, 636))
                sock.close()
                if result == 0:
                    ldaps_available.append(dc)
                else:
                    ldaps_unavailable.append(dc)
            except Exception:
                ldaps_unavailable.append(dc)

        if ldaps_unavailable and not ldaps_available:
            status, severity = STATUS_FAIL, SEVERITY_HIGH
            obs = f"LDAPS (port 636) is not reachable on any of {len(ldaps_unavailable)} tested DC(s)."
        elif ldaps_unavailable:
            status, severity = STATUS_WARN, SEVERITY_MEDIUM
            obs = f"LDAPS on {len(ldaps_available)} DC(s), unavailable on {len(ldaps_unavailable)}."
        else:
            status, severity = STATUS_PASS, SEVERITY_INFO
            obs = f"LDAPS (port 636) available on all {len(ldaps_available)} tested DC(s)."

        self.add_finding(
            test_id="LDAP-004",
            test_name="LDAPS Configuration",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description="LDAPS (LDAP over TLS, port 636) encrypts LDAP traffic.",
            observation=obs,
            remediation="Deploy certificates on all DCs to enable LDAPS.",
            affected_objects=ldaps_unavailable if ldaps_unavailable else ldaps_available,
            details={"ldaps_available": ldaps_available, "ldaps_unavailable": ldaps_unavailable},
        )

    def _check_null_base_dn(self):
        try:
            from ldap3 import Server, Connection, ALL, BASE
            dc_target = self.domain_info.get("dc_list", [self.options.get("dc_ip")])[0]
            server = Server(dc_target, port=389, get_info=ALL, connect_timeout=5)
            conn = Connection(server, auto_bind=True, receive_timeout=5)
            conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["*"],
            )
            info_attrs = {}
            if conn.entries:
                entry = conn.entries[0]
                for attr in entry.entry_attributes:
                    info_attrs[attr] = str(entry[attr])
            conn.unbind()

            self.add_finding(
                test_id="LDAP-005",
                test_name="RootDSE Null Base DN Query",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_LOW,
                description="RootDSE is accessible without authentication (normal per RFC 4512).",
                observation=f"RootDSE returned {len(info_attrs)} attribute(s) anonymously.",
                remediation="This is expected behavior. Consider network-level controls if concerned.",
                details={"attributes_found": list(info_attrs.keys())[:20]},
            )
        except Exception as e:
            self.add_finding(
                test_id="LDAP-005",
                test_name="RootDSE Null Base DN Query",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Anonymous RootDSE query was not successful.",
                observation=f"Error: {e}",
            )
