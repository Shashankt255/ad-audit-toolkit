TOOL_NAME = "AD Audit Toolkit"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR = "Shashank Shekhar"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_WARN = "WARN"
STATUS_INFO = "INFO"
STATUS_ERROR = "ERROR"
STATUS_SKIP = "SKIP"

DANGEROUS_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
}

PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners",
    "Cert Publishers",
]

UNSUPPORTED_OS_KEYWORDS = [
    "Windows XP",
    "Windows Vista",
    "Windows 7",
    "Windows 8",
    "Windows Server 2003",
    "Windows Server 2008",
    "Windows Server 2012",
]

STALE_DAYS_THRESHOLD = 90
PASSWORD_AGE_WARN_DAYS = 365

AD_RIGHTS_GUID = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

CERTIFICATE_DANGEROUS_EKUS = [
    "1.3.6.1.5.5.7.3.2",  # Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "2.5.29.37.0",  # Any Purpose
    "1.3.6.1.5.2.3.4",  # PKINIT Client Authentication
]

KERBEROS_ENCRYPTION_TYPES = {
    0x1: "DES-CBC-CRC",
    0x2: "DES-CBC-MD4",
    0x3: "DES-CBC-MD5",
    0x4: "DES3-CBC-MD5",
    0x11: "AES128-CTS-HMAC-SHA1-96",
    0x12: "AES256-CTS-HMAC-SHA1-96",
    0x17: "RC4-HMAC",
    0x18: "RC4-HMAC-EXP",
}

MITRE_MAPPING = {
    "KRB-001": "T1558.003",
    "KRB-002": "T1558.004",
    "USR-005": "T1558.004",
    "USR-009": "T1558.003",
    "ACL-001": "T1003.006",
    "DEL-001": "T1550.003",
    "DEL-002": "T1550.003",
    "DEL-004": "T1550.003",
    "CVE-001": "T1210",
    "CVE-002": "T1187",
    "CVE-003": "T1210",
    "CVE-006": "T1557.001",
    "SMB-001": "T1557.001",
    "SMB-002": "T1021.002",
    "ADCS-003": "T1649",
    "ADCS-004": "T1649",
    "ADCS-005": "T1649",
    "ADCS-007": "T1649",
    "ADCS-008": "T1649",
    "GPO-003": "T1552.006",
    "CMP-005": "T1134",
    "MISC-005": "T1134.005",
    "CVE-004": "T1078",
    "CVE-005": "T1649",
}

RISK_WEIGHTS = {
    SEVERITY_CRITICAL: 10,
    SEVERITY_HIGH: 7,
    SEVERITY_MEDIUM: 4,
    SEVERITY_LOW: 1,
    SEVERITY_INFO: 0,
}
