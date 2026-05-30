import json
import os
from datetime import datetime


OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")


def generate_report(domain: str, results: dict) -> dict:
    """
    Save scan results to output/<domain>_<timestamp>.json and a readable .txt summary.
    Returns a dict with the paths of generated files.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{domain.replace('.', '_')}_{timestamp}"
    json_path = os.path.join(OUTPUT_DIR, f"{base_name}.json")
    txt_path  = os.path.join(OUTPUT_DIR, f"{base_name}.txt")

    # ── JSON ──────────────────────────────────────────────────
    payload = {
        "domain":    domain,
        "timestamp": datetime.now().isoformat(),
        "results":   results,
    }
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    # ── TEXT SUMMARY ──────────────────────────────────────────
    with open(txt_path, "w") as f:
        _write_text(f, domain, results)

    _print_report_footer(json_path, txt_path)

    return {"json": json_path, "txt": txt_path}


# ─────────────────────────────────────────────
#  TEXT REPORT WRITER
# ─────────────────────────────────────────────

def _write_text(f, domain: str, results: dict):
    _w(f, "=" * 60)
    _w(f, f"  WebStalker Report — {domain}")
    _w(f, f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _w(f, "=" * 60)

    # ── WHOIS ─────────────────────────────────────────────────
    if "whois" in results:
        d = results["whois"]
        _w(f, "\n[WHOIS]")
        if d.get("error"):
            _w(f, f"  Error: {d['error']}")
        else:
            for label, key in [
                ("Registrar",       "registrar"),
                ("Org",             "org"),
                ("Country",         "country"),
                ("Creation date",   "creation_date"),
                ("Expiration date", "expiration_date"),
                ("DNSSEC",          "dnssec"),
            ]:
                if d.get(key):
                    _w(f, f"  {label:<20}: {d[key]}")
            if d.get("name_servers"):
                _w(f, f"  {'Name servers':<20}:")
                for ns in d["name_servers"]:
                    _w(f, f"      {ns}")

    # ── DNS ───────────────────────────────────────────────────
    if "dns" in results:
        d = results["dns"]
        _w(f, "\n[DNS Enumeration]")
        if d.get("error"):
            _w(f, f"  Error: {d['error']}")
        else:
            for rtype, records in d.get("records", {}).items():
                if records:
                    _w(f, f"  [{rtype}]")
                    for r in records:
                        _w(f, f"      {r}")

    # ── SUBDOMAINS ────────────────────────────────────────────
    if "subdomains" in results:
        d = results["subdomains"]
        _w(f, "\n[Subdomains]")
        for src, info in d.get("sources", {}).items():
            status = f"Error: {info['error']}" if info.get("error") else f"{info['count']} found"
            _w(f, f"  [{src}] {status}")
        subs = d.get("subdomains", [])
        if subs:
            _w(f, f"  Total: {len(subs)}")
            for s in subs:
                _w(f, f"      {s}")
        else:
            _w(f, "  No subdomains found.")

    # ── PORT SCAN ─────────────────────────────────────────────
    if "ports" in results:
        d = results["ports"]
        _w(f, "\n[Port Scan]")
        if d.get("error"):
            _w(f, f"  Error: {d['error']}")
        else:
            ports = d.get("ports", {})
            if ports:
                _w(f, f"  {'PORT':<8} {'SERVICE':<12} PRODUCT / VERSION")
                _w(f, f"  {'-'*50}")
                for port, info in ports.items():
                    detail = " ".join(filter(None, [info["product"], info["version"], info["extrainfo"]]))
                    _w(f, f"  {port:<8} {info['service']:<12} {detail}")
            else:
                _w(f, "  No open ports found.")
            for os_match in d.get("os", []):
                _w(f, f"  OS: {os_match['name']} (accuracy: {os_match['accuracy']}%)")

    # ── HTTP HEADERS ──────────────────────────────────────────
    if "headers" in results:
        d = results["headers"]
        _w(f, "\n[HTTP Headers]")
        if d.get("error"):
            _w(f, f"  Error: {d['error']}")
        else:
            _w(f, f"  URL    : {d.get('url')}")
            _w(f, f"  Status : {d.get('status_code')}")
            h_lower = {k.lower(): v for k, v in d.get("headers", {}).items()}
            for h in ["server", "x-powered-by", "via", "x-generator"]:
                if h in h_lower:
                    _w(f, f"  {h}: {h_lower[h]}")
            if d.get("security"):
                _w(f, "  [Security headers]")
                for h, v in d["security"].items():
                    _w(f, f"      {h}: {v}")
            if d.get("missing"):
                _w(f, "  [Missing security headers]")
                for h in d["missing"]:
                    _w(f, f"      [!] {h}")
            if d.get("cookies"):
                _w(f, "  [Cookies]")
                for c in d["cookies"]:
                    flags = []
                    if c["secure"]:   flags.append("Secure")
                    if c["httponly"]: flags.append("HttpOnly")
                    flags.append(f"SameSite={c['samesite']}")
                    _w(f, f"      {c['name']}  →  {', '.join(flags)}")

    # ── TECH DETECTION ────────────────────────────────────────
    if "tech" in results:
        d = results["tech"]
        _w(f, "\n[Tech Detection]")
        if d.get("error"):
            _w(f, f"  Error: {d['error']}")
        else:
            for label, key in [("CMS", "cms"), ("Framework", "framework"), ("WAF", "waf"), ("CDN", "cdn")]:
                if d.get(key):
                    _w(f, f"  [{label}] {', '.join(d[key])}")

    # ── FUZZING ───────────────────────────────────────────────
    if "dirfuzz" in results:
        d = results["dirfuzz"]
        _w(f, "\n[Dir/File Fuzzer]")
        if d.get("error"):
            _w(f, f"  Error: {d['error']}")
        else:
            findings = d.get("findings", [])
            _w(f, f"  {len(findings)} result(s) found")
            for hit in sorted(findings, key=lambda x: x["code"]):
                redirect = f"  →  {hit['redirect']}" if hit.get("redirect") else ""
                _w(f, f"  [{hit['code']}]  {hit['size']} B  {hit['path']}{redirect}")

    if "sensitive" in results:
        d = results["sensitive"]
        _w(f, "\n[Sensitive Files]")
        if d.get("error"):
            _w(f, f"  Error: {d['error']}")
        else:
            findings = d.get("findings", [])
            if findings:
                for hit in findings:
                    redirect = f"  →  {hit['redirect']}" if hit.get("redirect") else ""
                    _w(f, f"  [{hit['code']}]  {hit['path']}{redirect}")
            else:
                _w(f, "  Nothing found.")

    _w(f, "\n" + "=" * 60)


def _w(f, line: str):
    f.write(line + "\n")


def _print_report_footer(json_path: str, txt_path: str):
    print(f"\n{'='*60}")
    print(f"  Report saved:")
    print(f"      JSON : {json_path}")
    print(f"      TXT  : {txt_path}")
    print(f"{'='*60}\n")
