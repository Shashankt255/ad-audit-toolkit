from modules.base import BaseModule
from config import *


class GPOAudit(BaseModule):
    MODULE_NAME = "GPO Audit"
    MODULE_DESCRIPTION = "Enumerates Group Policy Objects and checks for security issues."

    def execute(self):
        self._enumerate_gpos()
        self._check_gpo_permissions()
        self._check_gpp_passwords()

    def _enumerate_gpos(self):
        entries = self.ldap_search(
            f"CN=Policies,CN=System,{self.get_domain_dn()}",
            "(objectClass=groupPolicyContainer)",
            attributes=["displayName", "cn", "gPCFileSysPath", "whenCreated", "whenChanged", "versionNumber"],
        )

        if not entries:
            self.add_finding(
                test_id="GPO-001",
                test_name="GPO Enumeration",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="No Group Policy Objects found or insufficient permissions.",
                observation="LDAP query returned no GPO objects.",
            )
            return

        gpo_list = []
        for entry in entries:
            gpo_list.append({
                "name": str(entry.displayName) if hasattr(entry, "displayName") else "N/A",
                "guid": str(entry.cn) if hasattr(entry, "cn") else "N/A",
                "path": str(entry.gPCFileSysPath) if hasattr(entry, "gPCFileSysPath") else "N/A",
                "created": str(entry.whenCreated) if hasattr(entry, "whenCreated") else "N/A",
                "modified": str(entry.whenChanged) if hasattr(entry, "whenChanged") else "N/A",
            })

        self.add_finding(
            test_id="GPO-001",
            test_name="GPO Enumeration",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Enumerated all Group Policy Objects in the domain.",
            observation=f"Found {len(gpo_list)} GPO(s).",
            affected_objects=[g["name"] for g in gpo_list],
            details={"gpos": gpo_list},
        )

    def _check_gpo_permissions(self):
        entries = self.ldap_search(
            f"CN=Policies,CN=System,{self.get_domain_dn()}",
            "(objectClass=groupPolicyContainer)",
            attributes=["displayName", "cn", "nTSecurityDescriptor"],
        )

        if not entries:
            self.add_finding(
                test_id="GPO-002",
                test_name="GPO Permissions",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No GPOs available for permission check.",
                observation="Cannot enumerate GPO permissions.",
            )
            return

        self.add_finding(
            test_id="GPO-002",
            test_name="GPO Permissions",
            category=self.MODULE_NAME,
            status=STATUS_INFO,
            severity=SEVERITY_MEDIUM,
            description=(
                "GPO permission analysis requires detailed ACL parsing. Review GPO "
                "ownership and write permissions to identify potential misconfigurations."
            ),
            observation=f"Found {len(entries)} GPO(s). Manual ACL review recommended using tools like BloodHound or GPOPermissions.",
            remediation="Ensure only Domain Admins and Group Policy Creator Owners have GPO write access.",
            affected_objects=[str(e.displayName) if hasattr(e, "displayName") else "N/A" for e in entries],
        )

    def _check_gpp_passwords(self):
        entries = self.ldap_search(
            f"CN=Policies,CN=System,{self.get_domain_dn()}",
            "(objectClass=groupPolicyContainer)",
            attributes=["displayName", "cn", "gPCFileSysPath"],
        )

        if not entries:
            self.add_finding(
                test_id="GPO-003",
                test_name="GPP Passwords (cpassword)",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No GPOs available.",
                observation="Cannot check for GPP passwords.",
            )
            return

        gpo_paths = []
        for entry in entries:
            path = str(entry.gPCFileSysPath) if hasattr(entry, "gPCFileSysPath") else ""
            name = str(entry.displayName) if hasattr(entry, "displayName") else "N/A"
            if path and path != "[]":
                gpo_paths.append({"name": name, "path": path})

        self.add_finding(
            test_id="GPO-003",
            test_name="GPP Passwords (cpassword)",
            category=self.MODULE_NAME,
            status=STATUS_WARN,
            severity=SEVERITY_HIGH,
            description=(
                "Group Policy Preferences (GPP) may contain encrypted passwords (cpassword) "
                "that can be trivially decrypted. The encryption key was published by Microsoft."
            ),
            observation=(
                f"Found {len(gpo_paths)} GPO(s) with SYSVOL paths. Manual inspection of "
                f"Groups.xml, Services.xml, ScheduledTasks.xml, and DataSources.xml files "
                f"in SYSVOL is required to detect cpassword entries."
            ),
            remediation=(
                "Remove any GPP XML files containing cpassword. Use LAPS instead for "
                "local admin password management. Apply MS14-025 to prevent new GPP "
                "credential storage."
            ),
            details={"gpo_paths": gpo_paths[:20]},
            cve="MS14-025",
        )
