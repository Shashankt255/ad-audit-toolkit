import time
import traceback
from dataclasses import dataclass, field
from typing import Optional
from config import *


@dataclass
class Finding:
    test_id: str
    test_name: str
    category: str
    status: str  # PASS, FAIL, WARN, INFO, ERROR, SKIP
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    observation: str = ""
    remediation: str = ""
    affected_objects: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    cve: Optional[str] = None
    mitre_technique: Optional[str] = None
    references: list = field(default_factory=list)


class BaseModule:
    MODULE_NAME = "Base"
    MODULE_DESCRIPTION = ""

    def __init__(self, ldap_conn, domain_info, options=None):
        self.ldap_conn = ldap_conn
        self.domain_info = domain_info
        self.options = options or {}
        self.findings: list[Finding] = []
        self.start_time = None
        self.end_time = None

    def add_finding(self, **kwargs):
        finding = Finding(**kwargs)
        self.findings.append(finding)
        return finding

    def ldap_search(self, search_base, search_filter, attributes=None, search_scope="SUBTREE"):
        try:
            from ldap3 import SUBTREE, BASE, LEVEL
            scope_map = {"SUBTREE": SUBTREE, "BASE": BASE, "LEVEL": LEVEL}
            scope = scope_map.get(search_scope, SUBTREE)
            self.ldap_conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes or ["*"],
            )
            return self.ldap_conn.entries
        except Exception as e:
            return []

    def get_domain_dn(self):
        return self.domain_info.get("domain_dn", "")

    def get_domain_name(self):
        return self.domain_info.get("domain_name", "")

    def run(self):
        self.start_time = time.time()
        try:
            self.execute()
        except Exception as e:
            self.add_finding(
                test_id=f"{self.MODULE_NAME}-ERR",
                test_name=f"{self.MODULE_NAME} Module Error",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description=f"Module encountered an error: {e}",
                observation=traceback.format_exc(),
            )
        self.end_time = time.time()
        return self.findings

    def execute(self):
        raise NotImplementedError

    @property
    def duration(self):
        if self.start_time and self.end_time:
            return round(self.end_time - self.start_time, 2)
        return 0
