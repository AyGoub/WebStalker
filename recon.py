#!/usr/bin/env python3
import argparse

from modules.passive import whois_lookup, dns_enumeration, subdomain_enum
from modules.active  import port_scan, http_headers, tech_detect
from modules.fuzzing import dir_fuzzer, sensitive_finder
from modules.report  import generate_report


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
    parser.add_argument("--fuzz",    action="store_true", help="Run all fuzzing modules")

    # ── passive ───────────────────────────────────────────────
    parser.add_argument("--whois",      action="store_true", help="WHOIS lookup")
    parser.add_argument("--dns",        action="store_true", help="DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Subdomain enum (HackerTarget + OTX)")
    parser.add_argument("--types", nargs="+", metavar="TYPE",
                        help="DNS record types (used with --dns). e.g. --types A MX NS")

    # ── active ────────────────────────────────────────────────
    parser.add_argument("--ports",   action="store_true", help="Port scan (nmap)")
    parser.add_argument("--headers", action="store_true", help="HTTP headers analysis")
    parser.add_argument("--tech",    action="store_true", help="Technology detection (CMS, WAF, CDN)")
    parser.add_argument("--port-range", default="1-1000", metavar="RANGE",
                        help="Port range for --ports (default: 1-1000). e.g. --port-range 1-65535")

    # ── fuzzing ───────────────────────────────────────────────
    parser.add_argument("--dirfuzz",   action="store_true", help="Directory/file brute-force")
    parser.add_argument("--sensitive", action="store_true", help="Sensitive file finder (.env, .git, backups...)")
    parser.add_argument("--wordlist",  default=None, metavar="PATH",
                        help="Custom wordlist for --dirfuzz (default: dirb common.txt)")
    parser.add_argument("--ext", nargs="+", metavar="EXT",
                        help="Extensions for --dirfuzz. e.g. --ext php bak html")
    parser.add_argument("--threads", type=int, default=20, metavar="N",
                        help="Threads for fuzzing (default: 20)")
    parser.add_argument("--codes", nargs="+", type=int, metavar="CODE",
                        help="HTTP codes to show (default: all interesting). e.g. --codes 200 403")

    # ── output ────────────────────────────────────────────────
    parser.add_argument("--no-report", action="store_true",
                        help="Do not save report to output/")

    args = parser.parse_args()

    any_specific = any([
        args.whois, args.dns, args.subdomains,
        args.ports, args.headers, args.tech,
        args.dirfuzz, args.sensitive,
    ])

    run_all     = not any_specific and not args.passive and not args.active and not args.fuzz
    run_passive = run_all or args.passive
    run_active  = run_all or args.active
    run_fuzz    = run_all or args.fuzz
    show_codes  = set(args.codes) if args.codes else None

    results = {}

    # ── passive ───────────────────────────────────────────────
    if run_passive or args.whois:
        results["whois"] = whois_lookup(args.domain)

    if run_passive or args.dns:
        results["dns"] = dns_enumeration(args.domain, record_types=args.types or None)

    if run_passive or args.subdomains:
        results["subdomains"] = subdomain_enum(args.domain)

    # ── active ────────────────────────────────────────────────
    if run_active or args.ports:
        results["ports"] = port_scan(args.domain, ports=args.port_range)

    if run_active or args.headers:
        results["headers"] = http_headers(args.domain)

    if run_active or args.tech:
        results["tech"] = tech_detect(args.domain)

    # ── fuzzing ───────────────────────────────────────────────
    if run_fuzz or args.dirfuzz:
        results["dirfuzz"] = dir_fuzzer(
            target=args.domain,
            wordlist=args.wordlist or "/usr/share/dirb/wordlists/common.txt",
            extensions=args.ext or [],
            threads=args.threads,
            show_codes=show_codes,
        )

    if run_fuzz or args.sensitive:
        results["sensitive"] = sensitive_finder(
            target=args.domain,
            threads=args.threads,
            show_codes=show_codes,
        )

    # ── rapport ───────────────────────────────────────────────
    if results and not args.no_report:
        generate_report(args.domain, results)


if __name__ == "__main__":
    main()
