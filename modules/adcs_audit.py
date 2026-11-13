from modules.base import BaseModule
from config import *


class ADCSAudit(BaseModule):
    MODULE_NAME = "AD CS Audit"
    MODULE_DESCRIPTION = "Checks for AD Certificate Services misconfigurations (ESC1-ESC11)."

    def execute(self):
        self._check_enrollment_services()
        self._check_esc1()
        self._check_esc2()
        self._check_esc3()
        self._check_esc4()
        self._check_esc6()
        self._check_esc8()
        self._check_esc11()

    def _get_config_dn(self):
        return self.domain_info.get("config_dn", f"CN=Configuration,{self.get_domain_dn()}")

    def _get_pki_base(self):
        return f"CN=Public Key Services,CN=Services,{self._get_config_dn()}"

    def _get_enrollment_services(self):
        return self.ldap_search(
            f"CN=Enrollment Services,{self._get_pki_base()}",
            "(objectClass=pKIEnrollmentService)",
            attributes=["cn", "dNSHostName", "cACertificateDN", "certificateTemplates", "flags"],
        )

    def _get_templates(self):
        return self.ldap_search(
            f"CN=Certificate Templates,{self._get_pki_base()}",
            "(objectClass=pKICertificateTemplate)",
            attributes=[
                "cn", "displayName", "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                "nTSecurityDescriptor", "msPKI-Template-Schema-Version",
            ],
        )

    def _check_enrollment_services(self):
        cas = self._get_enrollment_services()
        if not cas:
            self.add_finding(
                test_id="ADCS-001",
                test_name="Certificate Authority Enumeration",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="No AD Certificate Services enrollment services found.",
                observation="AD CS does not appear to be deployed in this domain.",
            )
            return

        ca_list = []
        for ca in cas:
            ca_list.append({
                "name": str(ca.cn) if hasattr(ca, "cn") else "N/A",
                "host": str(ca.dNSHostName) if hasattr(ca, "dNSHostName") else "N/A",
                "templates": list(ca.certificateTemplates.values) if hasattr(ca, "certificateTemplates") and ca.certificateTemplates else [],
            })

        self.add_finding(
            test_id="ADCS-001",
            test_name="Certificate Authority Enumeration",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Enumerated AD Certificate Services Enrollment Services.",
            observation=f"Found {len(ca_list)} Certificate Authority(ies).",
            affected_objects=[c["name"] for c in ca_list],
            details={"cas": ca_list},
        )

    def _has_dangerous_eku(self, entry):
        ekus = []
        if hasattr(entry, "pKIExtendedKeyUsage") and entry.pKIExtendedKeyUsage:
            ekus = list(entry.pKIExtendedKeyUsage.values)
        if not ekus:
            return True
        for eku in ekus:
            if str(eku) in CERTIFICATE_DANGEROUS_EKUS:
                return True
        return False

    def _check_esc1(self):
        templates = self._get_templates()
        if not templates:
            self.add_finding(
                test_id="ADCS-002",
                test_name="ESC1 - Enrollee Supplies Subject",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No certificate templates found to check.",
                observation="AD CS templates not available.",
            )
            return

        vulnerable = []
        for t in templates:
            name = str(t.cn) if hasattr(t, "cn") else "N/A"
            name_flag_raw = t["msPKI-Certificate-Name-Flag"].value if "msPKI-Certificate-Name-Flag" in t.entry_attributes else None
            if name_flag_raw is None:
                continue
            try:
                name_flag = int(str(name_flag_raw))
            except (ValueError, TypeError):
                continue

            enrollee_supplies_subject = bool(name_flag & 1)
            if enrollee_supplies_subject and self._has_dangerous_eku(t):
                vulnerable.append({
                    "template": name,
                    "nameFlag": name_flag,
                    "enrolleeSuppliesSubject": True,
                })

        if vulnerable:
            self.add_finding(
                test_id="ADCS-002",
                test_name="ESC1 - Enrollee Supplies Subject",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description=(
                    "Certificate templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and a "
                    "dangerous EKU (Client Authentication, Smart Card Logon, Any Purpose) allow "
                    "any enrollee to request a certificate for any user, including Domain Admins."
                ),
                observation=f"Found {len(vulnerable)} ESC1-vulnerable template(s).",
                remediation=(
                    "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from templates with client auth "
                    "EKUs, or restrict enrollment to specific high-trust groups. Use "
                    "CA certificate manager approval."
                ),
                affected_objects=[v["template"] for v in vulnerable],
                details={"templates": vulnerable},
                cve="ESC1",
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
            )
        else:
            self.add_finding(
                test_id="ADCS-002",
                test_name="ESC1 - Enrollee Supplies Subject",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No templates vulnerable to ESC1.",
                observation="No templates allow enrollee-supplied subject with dangerous EKUs.",
            )

    def _check_esc2(self):
        templates = self._get_templates()
        if not templates:
            self.add_finding(
                test_id="ADCS-003",
                test_name="ESC2 - Any Purpose EKU",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No certificate templates found.",
                observation="AD CS templates not available.",
            )
            return

        vulnerable = []
        for t in templates:
            name = str(t.cn) if hasattr(t, "cn") else "N/A"
            ekus = list(t.pKIExtendedKeyUsage.values) if hasattr(t, "pKIExtendedKeyUsage") and t.pKIExtendedKeyUsage else []
            eku_strs = [str(e) for e in ekus]
            if not eku_strs or "2.5.29.37.0" in eku_strs:
                vulnerable.append({"template": name, "ekus": eku_strs or ["(no EKU restriction)"]})

        if vulnerable:
            self.add_finding(
                test_id="ADCS-003",
                test_name="ESC2 - Any Purpose EKU",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description=(
                    "Templates with Any Purpose EKU or no EKU restriction can be used for "
                    "any purpose including client authentication."
                ),
                observation=f"Found {len(vulnerable)} template(s) with unrestricted EKU.",
                remediation="Restrict EKU on templates to only the required purposes.",
                affected_objects=[v["template"] for v in vulnerable],
                details={"templates": vulnerable},
                cve="ESC2",
            )
        else:
            self.add_finding(
                test_id="ADCS-003",
                test_name="ESC2 - Any Purpose EKU",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No templates with unrestricted EKU.",
                observation="All templates have specific EKU restrictions.",
            )

    def _check_esc3(self):
        templates = self._get_templates()
        if not templates:
            self.add_finding(
                test_id="ADCS-004",
                test_name="ESC3 - Certificate Request Agent",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No certificate templates found.",
                observation="AD CS templates not available.",
            )
            return

        agent_templates = []
        for t in templates:
            name = str(t.cn) if hasattr(t, "cn") else "N/A"
            ekus = list(t.pKIExtendedKeyUsage.values) if hasattr(t, "pKIExtendedKeyUsage") and t.pKIExtendedKeyUsage else []
            eku_strs = [str(e) for e in ekus]
            if "1.3.6.1.4.1.311.20.2.1" in eku_strs:
                agent_templates.append({"template": name})

        if agent_templates:
            self.add_finding(
                test_id="ADCS-004",
                test_name="ESC3 - Certificate Request Agent",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description=(
                    "Templates with the Certificate Request Agent EKU allow enrollment "
                    "agents to request certificates on behalf of other users."
                ),
                observation=f"Found {len(agent_templates)} Certificate Request Agent template(s).",
                remediation=(
                    "Restrict enrollment agent templates to specific trusted users. "
                    "Enable 'This number of authorized signatures' on target templates."
                ),
                affected_objects=[a["template"] for a in agent_templates],
                details={"templates": agent_templates},
                cve="ESC3",
            )
        else:
            self.add_finding(
                test_id="ADCS-004",
                test_name="ESC3 - Certificate Request Agent",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No Certificate Request Agent templates found.",
                observation="No ESC3-vulnerable templates detected.",
            )

    def _check_esc4(self):
        templates = self._get_templates()
        if not templates:
            self.add_finding(
                test_id="ADCS-005",
                test_name="ESC4 - Template ACL Misconfiguration",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No certificate templates found.",
                observation="AD CS templates not available.",
            )
            return

        self.add_finding(
            test_id="ADCS-005",
            test_name="ESC4 - Template ACL Misconfiguration",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_MEDIUM,
            description=(
                "ESC4 checks whether low-privileged users have write access to certificate "
                "templates. Full ACL parsing requires manual review."
            ),
            observation=f"Found {len(templates)} template(s). Manual ACL review recommended.",
            remediation=(
                "Review template ACLs to ensure only authorized groups have write permissions. "
                "Use tools like Certify or Certipy for detailed ACL analysis."
            ),
            affected_objects=[str(t.cn) if hasattr(t, "cn") else "N/A" for t in templates],
            references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
        )

    def _check_esc6(self):
        cas = self._get_enrollment_services()
        if not cas:
            self.add_finding(
                test_id="ADCS-006",
                test_name="ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No CAs found to check ESC6.",
                observation="AD CS not deployed.",
            )
            return

        ca_names = [str(ca.cn) if hasattr(ca, "cn") else "N/A" for ca in cas]
        self.add_finding(
            test_id="ADCS-006",
            test_name="ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_HIGH,
            description=(
                "ESC6 flag (EDITF_ATTRIBUTESUBJECTALTNAME2) is stored in the CA registry, "
                "not directly queryable via LDAP. Manual verification required."
            ),
            observation=f"Found {len(cas)} CA(s). Run 'certutil -config \"CA\" -getreg policy\\EditFlags' on each CA server to verify.",
            remediation="Remove the flag if set: certutil -config 'CA' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
            affected_objects=ca_names,
            cve="ESC6",
        )

    def _check_esc8(self):
        cas = self._get_enrollment_services()
        if not cas:
            self.add_finding(
                test_id="ADCS-007",
                test_name="ESC8 - Web Enrollment",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No CAs found.",
                observation="AD CS not deployed.",
            )
            return

        ca_hosts = []
        for ca in cas:
            host = str(ca.dNSHostName) if hasattr(ca, "dNSHostName") else None
            if host and host != "[]":
                ca_hosts.append(host)

        if ca_hosts:
            self.add_finding(
                test_id="ADCS-007",
                test_name="ESC8 - Web Enrollment (HTTP)",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description=(
                    "If AD CS web enrollment is enabled over HTTP (not HTTPS), it is "
                    "vulnerable to NTLM relay attacks (ESC8). Verify manually whether "
                    "/certsrv is accessible via HTTP on the CA host(s)."
                ),
                observation=f"CA host(s) identified: {', '.join(ca_hosts)}. Check for HTTP web enrollment.",
                remediation=(
                    "Disable HTTP web enrollment or enforce HTTPS with Extended Protection for "
                    "Authentication (EPA). Disable NTLM on the IIS site."
                ),
                affected_objects=ca_hosts,
                cve="ESC8",
            )
        else:
            self.add_finding(
                test_id="ADCS-007",
                test_name="ESC8 - Web Enrollment (HTTP)",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Could not determine CA hostnames for ESC8 check.",
                observation="No CA DNS hostnames available.",
            )

    def _check_esc11(self):
        cas = self._get_enrollment_services()
        if not cas:
            self.add_finding(
                test_id="ADCS-008",
                test_name="ESC11 - NTLM Relay to ICPR",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No CAs found.",
                observation="AD CS not deployed.",
            )
            return

        ca_names = [str(ca.cn) if hasattr(ca, "cn") else "N/A" for ca in cas]
        self.add_finding(
            test_id="ADCS-008",
            test_name="ESC11 - NTLM Relay to ICPR",
            category=self.MODULE_NAME,
            status=STATUS_WARN,
            severity=SEVERITY_HIGH,
            description=(
                "CAs that do not enforce IF_ENFORCEENCRYPTICERTREQUEST may be vulnerable "
                "to NTLM relay on the RPC certificate enrollment interface (ESC11). "
                "Verify on each CA server."
            ),
            observation=f"Found {len(cas)} CA(s). Manual verification of encryption enforcement required.",
            remediation="Enable IF_ENFORCEENCRYPTICERTREQUEST on all CAs to require encrypted connections.",
            affected_objects=ca_names,
            cve="ESC11",
        )
