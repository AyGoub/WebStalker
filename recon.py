#!/usr/bin/env python3
import argparse

from modules.passive import whois_lookup, dns_enumeration, subdomain_enum


def main():
    parser = argparse.ArgumentParser(
        prog="webstalker",
        description="WebStalker — Recon Tool\n\nSans options : tout se lance automatiquement.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")

    # ── filtres optionnels ────────────────────────────────────
    parser.add_argument("--whois",      action="store_true", help="Lancer uniquement le WHOIS")
    parser.add_argument("--dns",        action="store_true", help="Lancer uniquement le DNS")
    parser.add_argument("--subdomains", action="store_true", help="Lancer uniquement l'enum sous-domaines (crt.sh)")
    parser.add_argument(
        "--types", nargs="+", metavar="TYPE",
        help="Types DNS à interroger (utilisé avec --dns). ex: --types A MX NS TXT"
    )

    args = parser.parse_args()

    # Si aucune option choisie → tout lancer
    run_all = not args.whois and not args.dns and not args.subdomains

    if run_all or args.whois:
        whois_lookup(args.domain)

    if run_all or args.dns:
        dns_enumeration(args.domain, record_types=args.types or None)

    if run_all or args.subdomains:
        subdomain_enum(args.domain)


if __name__ == "__main__":
    main()
