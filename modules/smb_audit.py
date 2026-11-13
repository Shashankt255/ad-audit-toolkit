import socket
from modules.base import BaseModule
from config import *


class SMBAudit(BaseModule):
    MODULE_NAME = "SMB Audit"
    MODULE_DESCRIPTION = "Checks SMB signing, protocol versions, and share security on domain controllers."

    def execute(self):
        self._check_smb_signing()
        self._check_smbv1()
        self._check_null_session()
        self._check_shares()

    def _get_dc_targets(self):
        targets = self.domain_info.get("dc_list", [])
        if not targets:
            dc_ip = self.options.get("dc_ip")
            if dc_ip:
                targets = [dc_ip]
        return targets

    def _check_smb_signing(self):
        targets = self._get_dc_targets()
        if not targets:
            self.add_finding(
                test_id="SMB-001",
                test_name="SMB Signing",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC targets available for SMB signing check.",
                observation="Cannot determine DC hostnames/IPs.",
            )
            return

        not_required = []
        required = []
        errors = []

        for target in targets[:5]:
            try:
                from impacket.smbconnection import SMBConnection
                conn = SMBConnection(target, target, sess_port=445, timeout=self.options.get("timeout", 5))
                if conn.isSigningRequired():
                    required.append(target)
                else:
                    not_required.append(target)
                conn.close()
            except Exception as e:
                errors.append({"target": target, "error": str(e)})

        if not_required:
            self.add_finding(
                test_id="SMB-001",
                test_name="SMB Signing",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description=(
                    "SMB signing is not required on one or more domain controllers. "
                    "This allows SMB relay attacks."
                ),
                observation=f"{len(not_required)} DC(s) do not require SMB signing.",
                remediation=(
                    "Enable and require SMB signing on all domain controllers via Group Policy: "
                    "Computer Configuration > Policies > Windows Settings > Security Settings > "
                    "Local Policies > Security Options > 'Microsoft network server: Digitally "
                    "sign communications (always)' = Enabled."
                ),
                affected_objects=not_required,
                details={"not_required": not_required, "required": required, "errors": errors},
                references=["https://attack.mitre.org/techniques/T1557/001/"],
            )
        elif required:
            self.add_finding(
                test_id="SMB-001",
                test_name="SMB Signing",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="SMB signing is required on all tested domain controllers.",
                observation=f"All {len(required)} DC(s) require SMB signing.",
                details={"required": required, "errors": errors},
            )
        else:
            self.add_finding(
                test_id="SMB-001",
                test_name="SMB Signing",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description="Could not connect to any DC to check SMB signing.",
                observation=f"Connection errors on all {len(errors)} target(s).",
                details={"errors": errors},
            )

    def _check_smbv1(self):
        targets = self._get_dc_targets()
        if not targets:
            self.add_finding(
                test_id="SMB-002",
                test_name="SMBv1 Protocol",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC targets available.",
                observation="Cannot check SMBv1.",
            )
            return

        smbv1_enabled = []
        smbv1_disabled = []

        for target in targets[:5]:
            try:
                from impacket.smbconnection import SMBConnection
                from impacket.smb import SMB_DIALECT
                conn = SMBConnection(target, target, sess_port=445, timeout=self.options.get("timeout", 5), preferredDialect=SMB_DIALECT)
                smbv1_enabled.append(target)
                conn.close()
            except Exception:
                smbv1_disabled.append(target)

        if smbv1_enabled:
            self.add_finding(
                test_id="SMB-002",
                test_name="SMBv1 Protocol",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_HIGH,
                description=(
                    "SMBv1 is enabled on domain controller(s). SMBv1 has known vulnerabilities "
                    "including EternalBlue (MS17-010) and should be disabled."
                ),
                observation=f"{len(smbv1_enabled)} DC(s) accept SMBv1 connections.",
                remediation="Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                affected_objects=smbv1_enabled,
                details={"smbv1_enabled": smbv1_enabled, "smbv1_disabled": smbv1_disabled},
                cve="MS17-010",
            )
        else:
            self.add_finding(
                test_id="SMB-002",
                test_name="SMBv1 Protocol",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="SMBv1 does not appear to be enabled on tested DCs.",
                observation=f"Tested {len(smbv1_disabled)} DC(s), none accepted SMBv1.",
            )

    def _check_null_session(self):
        targets = self._get_dc_targets()
        if not targets:
            self.add_finding(
                test_id="SMB-003",
                test_name="SMB Null Session",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC targets available.",
                observation="Cannot check null sessions.",
            )
            return

        null_allowed = []
        null_denied = []

        for target in targets[:3]:
            try:
                from impacket.smbconnection import SMBConnection
                conn = SMBConnection(target, target, sess_port=445, timeout=self.options.get("timeout", 5))
                conn.login("", "")
                try:
                    shares = conn.listShares()
                    null_allowed.append({"target": target, "shares": len(shares)})
                except Exception:
                    null_allowed.append({"target": target, "shares": 0})
                conn.close()
            except Exception:
                null_denied.append(target)

        if null_allowed:
            self.add_finding(
                test_id="SMB-003",
                test_name="SMB Null Session",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_MEDIUM,
                description=(
                    "Null (anonymous) SMB sessions are accepted on one or more DCs. "
                    "This may allow unauthenticated enumeration."
                ),
                observation=f"{len(null_allowed)} DC(s) accept null SMB sessions.",
                remediation="Restrict anonymous access via Group Policy.",
                affected_objects=[n["target"] for n in null_allowed],
                details={"null_allowed": null_allowed, "null_denied": null_denied},
            )
        else:
            self.add_finding(
                test_id="SMB-003",
                test_name="SMB Null Session",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Null SMB sessions are rejected on tested DCs.",
                observation=f"All {len(null_denied)} tested DC(s) deny null sessions.",
            )

    def _check_shares(self):
        targets = self._get_dc_targets()
        if not targets:
            self.add_finding(
                test_id="SMB-004",
                test_name="SMB Share Enumeration",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No DC targets available.",
                observation="Cannot enumerate shares.",
            )
            return

        target = targets[0]
        username = self.options.get("username", "")
        password = self.options.get("password", "")
        domain = self.options.get("domain", "")

        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(target, target, sess_port=445, timeout=self.options.get("timeout", 5))
            if self.options.get("hashes"):
                lm, nt = self.options["hashes"].split(":")
                conn.login(username, "", domain, lm, nt)
            else:
                conn.login(username, password, domain)

            shares = conn.listShares()
            share_list = []
            for share in shares:
                share_name = share["shi1_netname"][:-1]
                share_type = share["shi1_type"]
                share_remark = share["shi1_remark"][:-1] if share["shi1_remark"] else ""
                share_list.append({
                    "name": share_name,
                    "type": share_type,
                    "remark": share_remark,
                })
            conn.close()

            self.add_finding(
                test_id="SMB-004",
                test_name="SMB Share Enumeration",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Enumerated SMB shares on the primary domain controller.",
                observation=f"Found {len(share_list)} share(s) on {target}.",
                affected_objects=[s["name"] for s in share_list],
                details={"shares": share_list, "target": target},
            )
        except Exception as e:
            self.add_finding(
                test_id="SMB-004",
                test_name="SMB Share Enumeration",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description="Could not enumerate SMB shares.",
                observation=f"Error: {e}",
            )
