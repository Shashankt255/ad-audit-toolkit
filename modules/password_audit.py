from datetime import datetime, timedelta, timezone
from modules.base import BaseModule, Finding
from config import *

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_datetime(ft):
    if ft is None or ft == 0:
        return None
    try:
        val = int(ft)
        if val <= 0:
            return None
        return WINDOWS_EPOCH + timedelta(microseconds=val // 10)
    except (ValueError, OverflowError):
        return None


def _nt_duration_to_days(val):
    if val is None:
        return 0
    try:
        v = abs(int(val))
        return v // (10_000_000 * 60 * 60 * 24) if v > 0 else 0
    except (ValueError, OverflowError):
        return 0


class PasswordAuditModule(BaseModule):
    MODULE_NAME = "Password Policy"
    MODULE_DESCRIPTION = "Audits domain password policies and fine-grained password policies"

    def execute(self):
        self._default_password_policy()
        self._lockout_policy()
        self._fine_grained_policies()
        self._old_passwords()

    # PWD-001
    def _default_password_policy(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domain)",
            attributes=[
                "minPwdLength", "maxPwdAge", "minPwdAge",
                "pwdHistoryLength", "pwdProperties", "lockoutThreshold",
                "lockoutDuration", "lockOutObservationWindow",
            ],
            search_scope="BASE",
        )
        if not entries:
            self.add_finding(
                test_id="PWD-001",
                test_name="Default Domain Password Policy",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description="Could not retrieve domain password policy.",
            )
            return

        e = entries[0]
        min_len = int(getattr(e, "minPwdLength", type("", (), {"value": 0})).value)
        max_age_raw = getattr(e, "maxPwdAge", None)
        max_age_days = _nt_duration_to_days(max_age_raw.value if max_age_raw else None)
        min_age_raw = getattr(e, "minPwdAge", None)
        min_age_days = _nt_duration_to_days(min_age_raw.value if min_age_raw else None)
        history = int(getattr(e, "pwdHistoryLength", type("", (), {"value": 0})).value)
        pwd_props = int(getattr(e, "pwdProperties", type("", (), {"value": 0})).value)
        complexity = bool(pwd_props & 1)

        issues = []
        if min_len < 12:
            issues.append(f"Minimum password length ({min_len}) is below recommended 12 characters")
        if max_age_days == 0:
            issues.append("Maximum password age is set to 0 (passwords never expire)")
        elif max_age_days > 365:
            issues.append(f"Maximum password age ({max_age_days} days) exceeds 365 days")
        if min_age_days == 0:
            issues.append("Minimum password age is 0 — users can cycle through history immediately")
        if history < 12:
            issues.append(f"Password history ({history}) is below recommended 12")
        if not complexity:
            issues.append("Password complexity requirement is DISABLED")

        obs = (
            f"Min Length: {min_len} | Max Age: {max_age_days} days | "
            f"Min Age: {min_age_days} days | History: {history} | "
            f"Complexity: {'Enabled' if complexity else 'DISABLED'}"
        )

        status = STATUS_FAIL if issues else STATUS_PASS
        severity = SEVERITY_HIGH if len(issues) >= 3 else (SEVERITY_MEDIUM if issues else SEVERITY_INFO)

        self.add_finding(
            test_id="PWD-001",
            test_name="Default Domain Password Policy",
            category=self.MODULE_NAME,
            status=status,
            severity=severity,
            description="The default domain password policy applies to all users not covered by a "
                        "fine-grained policy. Weak settings enable credential-based attacks.",
            observation=obs + ("\nIssues: " + "; ".join(issues) if issues else ""),
            remediation="Set minimum password length to 12+, enable complexity, enforce 12+ password history, "
                        "set a maximum age of 90-365 days, and a minimum age of at least 1 day."
                        if issues else "",
        )

    # PWD-002
    def _lockout_policy(self):
        entries = self.ldap_search(
            self.get_domain_dn(),
            "(objectClass=domain)",
            attributes=["lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"],
            search_scope="BASE",
        )
        if not entries:
            return

        e = entries[0]
        threshold = int(getattr(e, "lockoutThreshold", type("", (), {"value": 0})).value)
        duration_raw = getattr(e, "lockoutDuration", None)
        duration_min = 0
        if duration_raw and duration_raw.value:
            try:
                duration_min = abs(int(duration_raw.value)) // (10_000_000 * 60)
            except (ValueError, OverflowError):
                pass

        no_lockout = threshold == 0
        too_high = threshold > 10
        issues = []
        if no_lockout:
            issues.append("Account lockout threshold is 0 (lockout DISABLED)")
        elif too_high:
            issues.append(f"Lockout threshold ({threshold}) is too high — consider 5-10")
        if duration_min == 0 and not no_lockout:
            issues.append("Lockout duration is 0 — accounts stay locked until admin unlock")

        obs = f"Lockout Threshold: {threshold} | Lockout Duration: {duration_min} min"

        self.add_finding(
            test_id="PWD-002",
            test_name="Account Lockout Policy",
            category=self.MODULE_NAME,
            status=STATUS_WARN if issues else STATUS_PASS,
            severity=SEVERITY_MEDIUM if no_lockout else (SEVERITY_LOW if issues else SEVERITY_INFO),
            description="Account lockout policy prevents brute-force attacks but must balance security "
                        "with availability. This is an observation-only check — no lockout attempts are made.",
            observation=obs + ("\nIssues: " + "; ".join(issues) if issues else ""),
            remediation="Set lockout threshold to 5-10. Set lockout duration to 15-30 minutes. "
                        "Set observation window equal to lockout duration." if issues else "",
        )

    # PWD-003
    def _fine_grained_policies(self):
        entries = self.ldap_search(
            f"CN=Password Settings Container,CN=System,{self.get_domain_dn()}",
            "(objectClass=msDS-PasswordSettings)",
            attributes=[
                "cn", "msDS-PasswordSettingsPrecedence",
                "msDS-MinimumPasswordLength", "msDS-MaximumPasswordAge",
                "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
                "msDS-LockoutThreshold", "msDS-PSOAppliesTo",
                "msDS-PasswordReversibleEncryptionEnabled",
            ],
        )
        if not entries:
            self.add_finding(
                test_id="PWD-003",
                test_name="Fine-Grained Password Policies (PSOs)",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Fine-grained password policies allow different password requirements per group.",
                observation="No Fine-Grained Password Policies (PSOs) found. "
                            "All users follow the default domain password policy.",
            )
            return

        pso_details = []
        weak_psos = []
        for e in entries:
            name = str(getattr(e, "cn", "?"))
            prec = str(getattr(e, "msDS-PasswordSettingsPrecedence", type("", (), {"value": "?"})).value)
            min_len_raw = getattr(e, "msDS-MinimumPasswordLength", None)
            min_len = int(min_len_raw.value) if min_len_raw and min_len_raw.value else 0
            complexity_raw = getattr(e, "msDS-PasswordComplexityEnabled", None)
            complexity = str(complexity_raw.value).lower() == "true" if complexity_raw else False

            applies_raw = getattr(e, "msDS-PSOAppliesTo", None)
            applies = []
            if applies_raw:
                if hasattr(applies_raw, "values"):
                    applies = [str(v).split(",")[0].replace("CN=", "") for v in applies_raw.values]
                elif applies_raw.value:
                    applies = [str(applies_raw.value).split(",")[0].replace("CN=", "")]

            detail = (
                f"{name} | Precedence: {prec} | MinLen: {min_len} | "
                f"Complexity: {'Yes' if complexity else 'No'} | "
                f"Applies to: {', '.join(applies) if applies else 'None'}"
            )
            pso_details.append(detail)

            if min_len < 12 or not complexity:
                weak_psos.append(name)

        self.add_finding(
            test_id="PWD-003",
            test_name="Fine-Grained Password Policies (PSOs)",
            category=self.MODULE_NAME,
            status=STATUS_WARN if weak_psos else STATUS_INFO,
            severity=SEVERITY_MEDIUM if weak_psos else SEVERITY_INFO,
            description="Fine-grained password policies allow different password requirements per group.",
            observation=f"Found {len(entries)} PSO(s)."
                        + (f" {len(weak_psos)} have weak settings." if weak_psos else ""),
            affected_objects=pso_details,
            remediation="Ensure all PSOs enforce minimum 12-character passwords with complexity enabled."
                        if weak_psos else "",
        )

    # PWD-004
    def _old_passwords(self):
        threshold = datetime.now(timezone.utc) - timedelta(days=PASSWORD_AGE_WARN_DAYS)
        users = self.ldap_search(
            self.get_domain_dn(),
            "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attributes=["sAMAccountName", "pwdLastSet", "adminCount"],
        )

        found = []
        priv_found = []
        for u in users:
            raw = getattr(u, "pwdLastSet", None)
            if raw is None or raw.value is None:
                continue
            pwd_set = _filetime_to_datetime(raw.value)
            if pwd_set and pwd_set < threshold:
                sam = str(getattr(u, "sAMAccountName", "?"))
                days_ago = (datetime.now(timezone.utc) - pwd_set).days
                found.append(f"{sam} | Password age: {days_ago} days")
                ac = getattr(u, "adminCount", None)
                if ac is not None and str(ac.value) == "1":
                    priv_found.append(sam)

        severity = SEVERITY_HIGH if priv_found else (SEVERITY_MEDIUM if found else SEVERITY_INFO)

        self.add_finding(
            test_id="PWD-004",
            test_name=f"Passwords Older Than {PASSWORD_AGE_WARN_DAYS} Days",
            category=self.MODULE_NAME,
            status=STATUS_WARN if found else STATUS_PASS,
            severity=severity,
            description=f"Accounts with passwords unchanged for {PASSWORD_AGE_WARN_DAYS}+ days are "
                        "at higher risk of credential compromise.",
            observation=(
                f"{len(found)} enabled account(s) have passwords older than {PASSWORD_AGE_WARN_DAYS} days."
                + (f" {len(priv_found)} of these are privileged: {', '.join(priv_found)}." if priv_found else "")
            ),
            affected_objects=found[:100],
            remediation="Enforce password rotation for all accounts. Prioritize privileged accounts. "
                        "Consider implementing Managed Service Accounts for service credentials.",
        )
