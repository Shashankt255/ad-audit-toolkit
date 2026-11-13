#!/usr/bin/env python3
"""AD Audit Toolkit - Active Directory Security Assessment Tool"""
import argparse
import sys
import os
import time
import getpass
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import *


def parse_args():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION} - Active Directory Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ad_audit.py -d corp.local -u admin -dc 10.0.0.1
  python ad_audit.py -d corp.local -u admin -dc dc01.corp.local --use-ldaps
  python ad_audit.py -d corp.local -u admin -dc 10.0.0.1 -m kerberos,acl
  python ad_audit.py -d corp.local -u admin -dc 10.0.0.1 --hashes LM:NT
        """
    )
    if "--list-modules" in sys.argv:
        print(f"\n{TOOL_NAME} v{TOOL_VERSION} - Available Modules:\n")
        for name, (mod_path, cls_name) in AVAILABLE_MODULES.items():
            print(f"  {name:20s} -> {cls_name}")
        print(f"\nRun all: python ad_audit.py -d DOMAIN -u USER -dc DC_IP")
        print(f"Run specific: python ad_audit.py -d DOMAIN -u USER -dc DC_IP -m kerberos,acl,adcs\n")
        sys.exit(0)
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., corp.local)")
    parser.add_argument("-u", "--username", required=True, help="Domain username")
    parser.add_argument("-p", "--password", help="Domain password (prompted if not provided)")
    parser.add_argument("-dc", "--dc-ip", required=True, help="Domain controller IP or hostname")
    parser.add_argument("--use-ldaps", action="store_true", help="Use LDAPS (port 636)")
    parser.add_argument("--port", type=int, help="Custom LDAP port")
    parser.add_argument("-o", "--output", default="ad_audit_report.html", help="Output report filename")
    parser.add_argument("-m", "--modules", help="Comma-separated list of modules to run (default: all)")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--hashes", help="NTLM hash for pass-the-hash (LM:NT format)")
    parser.add_argument("--list-modules", action="store_true", help="List available modules and exit")
    return parser.parse_args()


AVAILABLE_MODULES = {
    "domain_recon": ("modules.domain_recon", "DomainRecon"),
    "user_audit": ("modules.user_audit", "UserAudit"),
    "group_audit": ("modules.group_audit", "GroupAudit"),
    "computer_audit": ("modules.computer_audit", "ComputerAudit"),
    "kerberos": ("modules.kerberos_audit", "KerberosAudit"),
    "acl": ("modules.acl_audit", "ACLAudit"),
    "adcs": ("modules.adcs_audit", "ADCSAudit"),
    "smb": ("modules.smb_audit", "SMBAudit"),
    "ldap": ("modules.ldap_audit", "LDAPAudit"),
    "password": ("modules.password_audit", "PasswordAudit"),
    "delegation": ("modules.delegation_audit", "DelegationAudit"),
    "dns": ("modules.dns_audit", "DNSAudit"),
    "cve": ("modules.cve_audit", "CVEAudit"),
    "misc": ("modules.misc_audit", "MiscAudit"),
    "gpo": ("modules.gpo_audit", "GPOAudit"),
}


def banner():
    try:
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        console.print(Panel(
            f"[bold blue]{TOOL_NAME}[/bold blue] v{TOOL_VERSION}\n"
            f"[dim]Active Directory Security Assessment Tool[/dim]\n"
            f"[dim]Author: {TOOL_AUTHOR}[/dim]",
            border_style="blue"
        ))
        return console
    except ImportError:
        print(f"\n  {TOOL_NAME} v{TOOL_VERSION}")
        print(f"  Active Directory Security Assessment Tool")
        print(f"  Author: {TOOL_AUTHOR}\n")
        return None


def connect_ldap(args):
    from ldap3 import Server, Connection, ALL, NTLM, Tls
    import ssl

    port = args.port
    use_ssl = args.use_ldaps

    if not port:
        port = 636 if use_ssl else 389

    tls_config = None
    if use_ssl:
        tls_config = Tls(validate=ssl.CERT_NONE)

    server = Server(
        args.dc_ip,
        port=port,
        use_ssl=use_ssl,
        get_info=ALL,
        connect_timeout=args.timeout,
        tls=tls_config,
    )

    domain_user = f"{args.domain}\\{args.username}"

    if args.hashes:
        lm_hash, nt_hash = args.hashes.split(":")
        conn = Connection(
            server,
            user=domain_user,
            password=lm_hash + ":" + nt_hash,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=args.timeout,
        )
    else:
        password = args.password or getpass.getpass(f"Password for {domain_user}: ")
        conn = Connection(
            server,
            user=domain_user,
            password=password,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=args.timeout,
        )

    return conn


def get_domain_info(conn, args):
    from ldap3 import SUBTREE

    domain_parts = args.domain.split(".")
    domain_dn = ",".join(f"DC={p}" for p in domain_parts)

    info = {
        "domain_name": args.domain,
        "domain_dn": domain_dn,
        "dc_ip": args.dc_ip,
        "dc_list": [args.dc_ip],
        "config_dn": f"CN=Configuration,{domain_dn}",
        "schema_dn": f"CN=Schema,CN=Configuration,{domain_dn}",
    }

    if conn.server.info:
        si = conn.server.info
        if hasattr(si, "other") and si.other:
            if "configurationNamingContext" in si.other:
                info["config_dn"] = si.other["configurationNamingContext"][0]
            if "schemaNamingContext" in si.other:
                info["schema_dn"] = si.other["schemaNamingContext"][0]

    conn.search(
        search_base=domain_dn,
        search_filter="(&(objectCategory=computer)(primaryGroupID=516))",
        search_scope=SUBTREE,
        attributes=["dNSHostName", "sAMAccountName"],
    )

    dc_hosts = []
    for entry in conn.entries:
        dns_name = str(entry.dNSHostName) if hasattr(entry, "dNSHostName") else None
        if dns_name and dns_name != "[]":
            dc_hosts.append(dns_name)

    if dc_hosts:
        info["dc_list"] = dc_hosts
    if args.dc_ip not in info["dc_list"]:
        info["dc_list"].append(args.dc_ip)

    return info


def load_modules(module_names=None):
    import importlib
    modules = []
    names = module_names or list(AVAILABLE_MODULES.keys())
    for name in names:
        name = name.strip().lower()
        if name not in AVAILABLE_MODULES:
            print(f"  [!] Unknown module: {name}, skipping")
            continue
        mod_path, class_name = AVAILABLE_MODULES[name]
        try:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, class_name)
            modules.append((name, cls))
        except Exception as e:
            print(f"  [!] Failed to load {name}: {e}")
    return modules


def print_msg(console, msg, style=""):
    if console:
        console.print(msg)
    else:
        import re
        clean = re.sub(r'\[/?[^\]]+\]', '', msg)
        print(clean)


def main():
    args = parse_args()
    console = banner()

    if args.list_modules:
        print("\nAvailable modules:")
        for name, (mod_path, cls_name) in AVAILABLE_MODULES.items():
            print(f"  {name:20s} -> {cls_name}")
        print(f"\nRun all: python ad_audit.py -d DOMAIN -u USER -dc DC_IP")
        print(f"Run specific: python ad_audit.py -d DOMAIN -u USER -dc DC_IP -m kerberos,acl,adcs")
        sys.exit(0)

    if not args.password and not args.hashes:
        args.password = getpass.getpass(f"Password for {args.domain}\\{args.username}: ")

    print_msg(console, f"\n[bold]Connecting to {args.dc_ip}...[/bold]")
    try:
        conn = connect_ldap(args)
        print_msg(console, f"[green]  + Connected via {'LDAPS' if args.use_ldaps else 'LDAP'}[/green]")
    except Exception as e:
        print_msg(console, f"[red]  - Connection failed: {e}[/red]")
        sys.exit(1)

    print_msg(console, "[bold]Gathering domain information...[/bold]")
    domain_info = get_domain_info(conn, args)
    print_msg(console, f"[green]  + Domain: {domain_info['domain_name']}[/green]")
    print_msg(console, f"[green]  + Domain DN: {domain_info['domain_dn']}[/green]")
    print_msg(console, f"[green]  + DCs found: {len(domain_info['dc_list'])}[/green]")

    options = {
        "username": args.username,
        "password": args.password,
        "domain": args.domain,
        "dc_ip": args.dc_ip,
        "hashes": args.hashes,
        "timeout": args.timeout,
        "verbose": args.verbose,
        "use_ldaps": args.use_ldaps,
    }

    selected = args.modules.split(",") if args.modules else None
    module_list = load_modules(selected)
    print_msg(console, f"\n[bold]Running {len(module_list)} audit module(s)...[/bold]\n")

    all_findings = []
    module_results = []

    for mod_name, mod_cls in module_list:
        print_msg(console, f"  [dim]> {mod_cls.MODULE_NAME}...[/dim]")
        instance = mod_cls(conn, domain_info, options)
        findings = instance.run()
        all_findings.extend(findings)
        module_results.append({
            "name": instance.MODULE_NAME,
            "description": instance.MODULE_DESCRIPTION,
            "findings": findings,
            "duration": instance.duration,
        })
        f_count = sum(1 for f in findings if f.status == STATUS_FAIL)
        w_count = sum(1 for f in findings if f.status == STATUS_WARN)
        print_msg(console, f"  [green]  + {mod_cls.MODULE_NAME}[/green] - {len(findings)} findings ({f_count} FAIL, {w_count} WARN) [{instance.duration}s]")

    print_msg(console, f"\n[bold]{'='*50}[/bold]")
    print_msg(console, f"[bold]Audit Complete![/bold]")

    total = len(all_findings)
    crit = sum(1 for f in all_findings if f.severity == SEVERITY_CRITICAL)
    high = sum(1 for f in all_findings if f.severity == SEVERITY_HIGH)
    med = sum(1 for f in all_findings if f.severity == SEVERITY_MEDIUM)
    low = sum(1 for f in all_findings if f.severity == SEVERITY_LOW)
    info_count = sum(1 for f in all_findings if f.severity == SEVERITY_INFO)

    fail = sum(1 for f in all_findings if f.status == STATUS_FAIL)
    warn = sum(1 for f in all_findings if f.status == STATUS_WARN)
    pass_count = sum(1 for f in all_findings if f.status == STATUS_PASS)

    print_msg(console, f"\n  Total findings: {total}")
    print_msg(console, f"  [red]CRITICAL: {crit}[/red]  [yellow]HIGH: {high}[/yellow]  MEDIUM: {med}  LOW: {low}  INFO: {info_count}")
    print_msg(console, f"  FAIL: {fail}  WARN: {warn}  PASS: {pass_count}")

    print_msg(console, f"\n[bold]Generating report...[/bold]")
    from reporting.html_report import generate_report

    total_duration = sum(m["duration"] for m in module_results)
    metadata = {
        "domain": domain_info["domain_name"],
        "dc": args.dc_ip,
        "username": f"{args.domain}\\{args.username}",
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": f"{total_duration:.1f}s",
        "modules_run": len(module_results),
        "protocol": "LDAPS" if args.use_ldaps else "LDAP",
        "domain_dn": domain_info["domain_dn"],
        "forest": domain_info.get("forest_name", domain_info["domain_name"]),
    }

    output_path = args.output
    generate_report(all_findings, metadata, output_path)
    print_msg(console, f"[green]  + Report saved to: {os.path.abspath(output_path)}[/green]")

    conn.unbind()
    print_msg(console, "\n[dim]Done. Stay safe![/dim]")


if __name__ == "__main__":
    main()
