#!/usr/bin/env python3
import argparse

from modules.passive import whois_lookup, dns_enumeration, subdomain_enum
from modules.active  import port_scan, http_headers, tech_detect


def main():
    parser = argparse.ArgumentParser(
        prog="webstalker",
        description="WebStalker — Recon Tool\n\nSans options : tout se lance.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")

    # ── groupes ───────────────────────────────────────────────
    parser.add_argument("--passive", action="store_true", help="Run all passive modules")
    parser.add_argument("--active",  action="store_true", help="Run all active modules")

    # ── passive (individuel) ──────────────────────────────────
    parser.add_argument("--whois",      action="store_true", help="WHOIS lookup")
    parser.add_argument("--dns",        action="store_true", help="DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Subdomain enum (HackerTarget + OTX)")
    parser.add_argument("--types", nargs="+", metavar="TYPE",
                        help="DNS record types (used with --dns). e.g. --types A MX NS")

    # ── active (individuel) ───────────────────────────────────
    parser.add_argument("--ports",   action="store_true", help="Port scan (nmap)")
    parser.add_argument("--headers", action="store_true", help="HTTP headers analysis")
    parser.add_argument("--tech",    action="store_true", help="Technology detection (CMS, WAF, CDN)")
    parser.add_argument("--port-range", default="1-1000", metavar="RANGE",
                        help="Port range for --ports (default: 1-1000). e.g. --port-range 1-65535")

    args = parser.parse_args()

    any_specific = any([
        args.whois, args.dns, args.subdomains,
        args.ports, args.headers, args.tech,
    ])

    run_all     = not any_specific and not args.passive and not args.active
    run_passive = run_all or args.passive
    run_active  = run_all or args.active

    # ── passive ───────────────────────────────────────────────
    if run_passive or args.whois:
        whois_lookup(args.domain)

    if run_passive or args.dns:
        dns_enumeration(args.domain, record_types=args.types or None)

    if run_passive or args.subdomains:
        subdomain_enum(args.domain)

    # ── active ────────────────────────────────────────────────
    if run_active or args.ports:
        port_scan(args.domain, ports=args.port_range)

    if run_active or args.headers:
        http_headers(args.domain)

    if run_active or args.tech:
        tech_detect(args.domain)


if __name__ == "__main__":
    main()
