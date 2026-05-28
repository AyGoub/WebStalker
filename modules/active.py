import os
import nmap
import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
TIMEOUT = 10


# ─────────────────────────────────────────────
#  PORT SCAN (nmap)
# ─────────────────────────────────────────────

def port_scan(target: str, ports: str = "1-1000", verbose: bool = True) -> dict:
    """
    Scan open ports with service/version detection and OS fingerprinting.
    Requires nmap installed on the system and root for OS detection.
    """
    result = {
        "target": target,
        "ports": {},
        "os": [],
        "error": None,
    }

    try:
        nm = nmap.PortScanner()
        is_root = os.geteuid() == 0
        args = "-sV -O --version-intensity 5 -T4" if is_root else "-sV --version-intensity 5 -T4"
        nm.scan(hosts=target, ports=ports, arguments=args)

        hosts = nm.all_hosts()
        if not hosts:
            result["error"] = f"Host '{target}' unreachable or not found"
            if verbose:
                _print_ports(result)
            return result

        host = nm[hosts[0]]

        for proto in host.all_protocols():
            for port, info in sorted(host[proto].items()):
                if info["state"] == "open":
                    result["ports"][port] = {
                        "proto":   proto,
                        "state":   info["state"],
                        "service": info.get("name", ""),
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                        "extrainfo": info.get("extrainfo", ""),
                    }

        if "osmatch" in host:
            for match in host["osmatch"][:3]:
                result["os"].append({
                    "name":     match["name"],
                    "accuracy": match["accuracy"],
                })

    except nmap.PortScannerError as exc:
        result["error"] = f"nmap error: {exc}"
    except Exception as exc:
        result["error"] = str(exc)

    if verbose:
        _print_ports(result)

    return result


def _print_ports(data: dict):
    print(f"\n{'='*55}")
    print(f"  Port Scan — {data['target']}")
    print(f"{'='*55}")
    if data["error"]:
        print(f"  [!] {data['error']}")
        return

    if not data["ports"]:
        print("  No open ports found.")
    else:
        print(f"\n  {'PORT':<8} {'PROTO':<6} {'SERVICE':<12} {'PRODUCT / VERSION'}")
        print(f"  {'-'*60}")
        for port, info in data["ports"].items():
            product = info["product"]
            version = info["version"]
            extra   = info["extrainfo"]
            detail  = " ".join(filter(None, [product, version, extra]))
            print(f"  {port:<8} {info['proto']:<6} {info['service']:<12} {detail}")

    if data["os"]:
        print(f"\n  OS Detection:")
        for os in data["os"]:
            print(f"      {os['name']}  (accuracy: {os['accuracy']}%)")
    print()


# ─────────────────────────────────────────────
#  HTTP HEADERS
# ─────────────────────────────────────────────

SECURITY_HEADERS = [
    "server", "x-powered-by", "x-frame-options", "x-content-type-options",
    "strict-transport-security", "content-security-policy",
    "access-control-allow-origin", "x-xss-protection",
    "referrer-policy", "permissions-policy",
]


def http_headers(target: str, verbose: bool = True) -> dict:
    """
    Grab HTTP response headers and analyse security posture.
    Tries HTTPS first, falls back to HTTP.
    """
    result = {
        "target": target,
        "url": None,
        "status_code": None,
        "headers": {},
        "cookies": [],
        "security": {},
        "missing": [],
        "error": None,
    }

    url = _resolve_url(target)
    if url is None:
        result["error"] = "Target unreachable on HTTP and HTTPS"
        if verbose:
            _print_headers(result)
        return result

    result["url"] = url

    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                            verify=False, allow_redirects=True)
        result["status_code"] = resp.status_code
        result["headers"] = dict(resp.headers)

        # Security header analysis
        h_lower = {k.lower(): v for k, v in resp.headers.items()}
        important = ["strict-transport-security", "content-security-policy",
                     "x-frame-options", "x-content-type-options",
                     "referrer-policy", "permissions-policy"]
        for h in important:
            if h in h_lower:
                result["security"][h] = h_lower[h]
            else:
                result["missing"].append(h)

        # Cookie analysis
        for cookie in resp.cookies:
            result["cookies"].append({
                "name":     cookie.name,
                "secure":   cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie._rest).lower(),
                "samesite": cookie._rest.get("SameSite", "not set"),
            })

    except requests.RequestException as exc:
        result["error"] = str(exc)

    if verbose:
        _print_headers(result)

    return result


def _resolve_url(target: str) -> str | None:
    target = target.rstrip("/")
    for scheme in ("https", "http"):
        url = target if target.startswith("http") else f"{scheme}://{target}"
        try:
            r = requests.head(url, headers=HEADERS, timeout=TIMEOUT,
                              verify=False, allow_redirects=True)
            if r.status_code < 600:
                return url
        except Exception:
            continue
    return None


def _print_headers(data: dict):
    print(f"\n{'='*55}")
    print(f"  HTTP Headers — {data['target']}")
    print(f"{'='*55}")
    if data["error"]:
        print(f"  [!] {data['error']}")
        return

    print(f"  URL    : {data['url']}")
    print(f"  Status : {data['status_code']}")

    h_lower = {k.lower(): v for k, v in data["headers"].items()}
    interesting = ["server", "x-powered-by", "via", "x-generator",
                   "x-aspnet-version", "x-aspnetmvc-version"]
    print(f"\n  [Info headers]")
    for h in interesting:
        if h in h_lower:
            print(f"      {h}: {h_lower[h]}")

    print(f"\n  [Security headers]")
    for h, v in data["security"].items():
        print(f"      {h}: {v}")
    if data["missing"]:
        print(f"\n  [Missing security headers]")
        for h in data["missing"]:
            print(f"      [!] {h}")

    if data["cookies"]:
        print(f"\n  [Cookies]")
        for c in data["cookies"]:
            flags = []
            if c["secure"]:   flags.append("Secure")
            if c["httponly"]: flags.append("HttpOnly")
            flags.append(f"SameSite={c['samesite']}")
            print(f"      {c['name']}  →  {', '.join(flags)}")
    print()


# ─────────────────────────────────────────────
#  TECHNOLOGY DETECTION
# ─────────────────────────────────────────────

CMS_SIGNATURES = {
    "WordPress":  [r"wp-content", r"wp-includes", r"wp-json", r"/wp-login\.php"],
    "Joomla":     [r"/components/com_", r"Joomla!", r"/media/jui/"],
    "Drupal":     [r"Drupal\.settings", r"/sites/default/files", r"X-Generator: Drupal"],
    "Magento":    [r"Mage\.Cookies", r"/skin/frontend/", r"magento"],
    "Shopify":    [r"cdn\.shopify\.com", r"Shopify\.theme"],
    "PrestaShop": [r"prestashop", r"/themes/default-bootstrap/"],
}

FRAMEWORK_SIGNATURES = {
    "Laravel":       [r"laravel_session", r"X-Powered-By: PHP", r"XSRF-TOKEN"],
    "Django":        [r"csrfmiddlewaretoken", r"django", r"X-Frame-Options: SAMEORIGIN"],
    "Ruby on Rails": [r"X-Powered-By: Phusion Passenger", r"_rails_session", r"ruby"],
    "ASP.NET":       [r"X-Powered-By: ASP\.NET", r"ASP\.NET_SessionId", r"__VIEWSTATE"],
    "Next.js":       [r"__NEXT_DATA__", r"_next/static"],
    "Express.js":    [r"X-Powered-By: Express"],
    "Spring":        [r"JSESSIONID", r"X-Application-Context"],
}

WAF_SIGNATURES = {
    "Cloudflare":   [r"cf-ray", r"__cfduid", r"cloudflare"],
    "AWS WAF":      [r"x-amzn-requestid", r"awselb"],
    "ModSecurity":  [r"mod_security", r"NOYB"],
    "Sucuri":       [r"x-sucuri-id", r"sucuri"],
    "Akamai":       [r"akamai", r"x-akamai-transformed"],
    "Imperva":      [r"x-iinfo", r"incap_ses", r"visid_incap"],
    "Barracuda":    [r"barra_counter_session"],
    "F5 BIG-IP":    [r"BigIP", r"F5_ST", r"TS[a-zA-Z0-9]{8}="],
}

CDN_SIGNATURES = {
    "Cloudflare": [r"cf-ray", r"cf-cache-status"],
    "Fastly":     [r"x-served-by", r"x-cache.*fastly", r"fastly-restarts"],
    "AWS CloudFront": [r"x-amz-cf-id", r"via.*cloudfront"],
    "Akamai":     [r"x-akamai", r"akamai-origin-hop"],
    "Varnish":    [r"x-varnish", r"via.*varnish"],
    "Nginx":      [r"server: nginx"],
}


def _match_signatures(sigs: dict, haystack: str) -> list[str]:
    found = []
    for name, patterns in sigs.items():
        if any(re.search(p, haystack, re.IGNORECASE) for p in patterns):
            found.append(name)
    return found


def tech_detect(target: str, verbose: bool = True) -> dict:
    """
    Detect CMS, frameworks, WAF and CDN from HTTP headers + HTML body.
    """
    result = {
        "target": target,
        "url": None,
        "cms":       [],
        "framework": [],
        "waf":       [],
        "cdn":       [],
        "error": None,
    }

    url = _resolve_url(target)
    if url is None:
        result["error"] = "Target unreachable on HTTP and HTTPS"
        if verbose:
            _print_tech(result)
        return result

    result["url"] = url

    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                            verify=False, allow_redirects=True)

        # Build a single haystack: headers + body
        header_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        cookie_str = "\n".join(
            f"{c.name}={c.value}" for c in resp.cookies
        )
        body       = resp.text[:50_000]
        haystack   = "\n".join([header_str, cookie_str, body])

        result["cms"]       = _match_signatures(CMS_SIGNATURES, haystack)
        result["framework"] = _match_signatures(FRAMEWORK_SIGNATURES, haystack)
        result["waf"]       = _match_signatures(WAF_SIGNATURES, haystack)
        result["cdn"]       = _match_signatures(CDN_SIGNATURES, haystack)

    except requests.RequestException as exc:
        result["error"] = str(exc)

    if verbose:
        _print_tech(result)

    return result


def _print_tech(data: dict):
    print(f"\n{'='*55}")
    print(f"  Tech Detection — {data['target']}")
    print(f"{'='*55}")
    if data["error"]:
        print(f"  [!] {data['error']}")
        return

    categories = [
        ("CMS",       data["cms"]),
        ("Framework", data["framework"]),
        ("WAF",       data["waf"]),
        ("CDN",       data["cdn"]),
    ]
    nothing = True
    for label, findings in categories:
        if findings:
            nothing = False
            print(f"  [{label}]")
            for f in findings:
                print(f"      {f}")
    if nothing:
        print("  Nothing detected.")
    print()
