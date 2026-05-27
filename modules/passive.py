import whois
import dns.resolver
import json
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────
#  WHOIS LOOKUP
# ─────────────────────────────────────────────

def whois_lookup(domain: str, verbose: bool = True) -> dict:
    """
    Perform a WHOIS lookup for the given domain.

    Returns a dict with the most useful fields extracted from the raw result.
    """
    result = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "emails": [],
        "org": None,
        "country": None,
        "dnssec": None,
        "raw": None,
        "error": None,
    }

    try:
        w = whois.whois(domain)

        def _serialize_date(value):
            if isinstance(value, list):
                return [v.isoformat() if isinstance(v, datetime) else str(v) for v in value]
            if isinstance(value, datetime):
                return value.isoformat()
            return str(value) if value else None

        result["registrar"]       = w.registrar
        result["creation_date"]   = _serialize_date(w.creation_date)
        result["expiration_date"] = _serialize_date(w.expiration_date)
        result["updated_date"]    = _serialize_date(w.updated_date)
        result["org"]             = w.org
        result["country"]         = w.country
        result["dnssec"]          = w.dnssec

        # Normalize lists
        result["name_servers"] = (
            [ns.lower() for ns in w.name_servers] if w.name_servers else []
        )
        result["status"] = (
            w.status if isinstance(w.status, list) else [w.status]
        ) if w.status else []
        result["emails"] = (
            w.emails if isinstance(w.emails, list) else [w.emails]
        ) if w.emails else []

    except Exception as exc:
        result["error"] = str(exc)

    if verbose:
        _print_whois(result)

    return result


def _print_whois(data: dict):
    print(f"\n{'='*50}")
    print(f"  WHOIS — {data['domain']}")
    print(f"{'='*50}")
    if data["error"]:
        print(f"  [!] Error: {data['error']}")
        return
    fields = [
        ("Registrar",       data["registrar"]),
        ("Org",             data["org"]),
        ("Country",         data["country"]),
        ("Creation date",   data["creation_date"]),
        ("Expiration date", data["expiration_date"]),
        ("Updated date",    data["updated_date"]),
        ("DNSSEC",          data["dnssec"]),
    ]
    for label, value in fields:
        if value:
            print(f"  {label:<20}: {value}")
    if data["name_servers"]:
        print(f"  {'Name servers':<20}:")
        for ns in data["name_servers"]:
            print(f"      {ns}")
    if data["status"]:
        print(f"  {'Status':<20}:")
        for s in data["status"]:
            print(f"      {s}")
    if data["emails"]:
        print(f"  {'Emails':<20}:")
        for e in data["emails"]:
            print(f"      {e}")
    print()


# ─────────────────────────────────────────────
#  DNS ENUMERATION
# ─────────────────────────────────────────────

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]


def dns_enumeration(domain: str, record_types: list | None = None, verbose: bool = True) -> dict:
    """
    Enumerate DNS records for the given domain.

    Args:
        domain:       Target domain (e.g. 'example.com')
        record_types: List of record types to query. Defaults to DNS_RECORD_TYPES.
        verbose:      Print results to stdout.

    Returns a dict mapping each record type to its results (list of strings or error string).
    """
    if record_types is None:
        record_types = DNS_RECORD_TYPES

    resolver = dns.resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 10

    results = {"domain": domain, "records": {}, "error": None}

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = _parse_answers(rtype, answers)
            results["records"][rtype] = records
        except dns.resolver.NXDOMAIN:
            results["error"] = f"Domain '{domain}' does not exist (NXDOMAIN)"
            break
        except dns.resolver.NoAnswer:
            results["records"][rtype] = []
        except dns.resolver.NoNameservers:
            results["records"][rtype] = ["[no nameservers available]"]
        except dns.exception.Timeout:
            results["records"][rtype] = ["[timeout]"]
        except Exception as exc:
            results["records"][rtype] = [f"[error: {exc}]"]

    if verbose:
        _print_dns(results)

    return results


def _parse_answers(rtype: str, answers) -> list:
    parsed = []
    for rdata in answers:
        if rtype == "MX":
            parsed.append(f"{rdata.preference} {rdata.exchange}")
        elif rtype == "SOA":
            parsed.append(
                f"mname={rdata.mname} rname={rdata.rname} "
                f"serial={rdata.serial} refresh={rdata.refresh} "
                f"retry={rdata.retry} expire={rdata.expire} minimum={rdata.minimum}"
            )
        elif rtype == "SRV":
            parsed.append(f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}")
        else:
            parsed.append(str(rdata))
    return parsed


def _print_dns(data: dict):
    print(f"\n{'='*50}")
    print(f"  DNS Enumeration — {data['domain']}")
    print(f"{'='*50}")
    if data["error"]:
        print(f"  [!] {data['error']}")
        return
    for rtype, records in data["records"].items():
        if not records:
            continue
        print(f"\n  [{rtype}]")
        for r in records:
            print(f"      {r}")
    print()


# ─────────────────────────────────────────────
#  SUBDOMAIN ENUMERATION — PASSIVE
#  Sources : HackerTarget + AlienVault OTX
#  Lancées en parallèle, résultats fusionnés
# ─────────────────────────────────────────────

HEADERS = {"User-Agent": "WebStalker/1.0"}
TIMEOUT  = 15


def _fetch_hackertarget(domain: str) -> tuple[str, set, str | None]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            text = r.read().decode()
        if "error check your" in text.lower() or "api count exceeded" in text.lower():
            return ("hackertarget", set(), text.strip())
        subs = set()
        for line in text.splitlines():
            host = line.split(",")[0].strip().lower()
            if host.endswith(f".{domain}"):
                subs.add(host)
        return ("hackertarget", subs, None)
    except Exception as exc:
        return ("hackertarget", set(), str(exc))


def _fetch_otx(domain: str) -> tuple[str, set, str | None]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read().decode())
        subs = set()
        for entry in data.get("passive_dns", []):
            host = entry.get("hostname", "").strip().lower()
            if host.endswith(f".{domain}"):
                subs.add(host)
        return ("alienvault", subs, None)
    except Exception as exc:
        return ("alienvault", set(), str(exc))


def subdomain_enum(domain: str, verbose: bool = True) -> dict:
    """
    Discover subdomains passively using HackerTarget and AlienVault OTX (parallel).
    Results are merged and deduplicated.
    """
    result = {
        "domain": domain,
        "sources": {},
        "subdomains": [],
        "count": 0,
    }

    fetchers = [_fetch_hackertarget, _fetch_otx]
    all_subs: set = set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(fn, domain): fn for fn in fetchers}
        for future in as_completed(futures):
            source, subs, error = future.result()
            result["sources"][source] = {
                "count": len(subs),
                "error": error,
            }
            all_subs |= subs

    result["subdomains"] = sorted(all_subs)
    result["count"] = len(result["subdomains"])

    if verbose:
        _print_subdomains(result)

    return result


def _print_subdomains(data: dict):
    print(f"\n{'='*50}")
    print(f"  Subdomains — {data['domain']}")
    print(f"{'='*50}")

    for source, info in data["sources"].items():
        status = f"[!] {info['error']}" if info["error"] else f"{info['count']} found"
        print(f"  [{source}] {status}")

    if not data["subdomains"]:
        print("\n  No subdomains found.")
        return

    print(f"\n  Total : {data['count']} unique subdomain(s)\n")
    for sub in data["subdomains"]:
        print(f"      {sub}")
    print()
