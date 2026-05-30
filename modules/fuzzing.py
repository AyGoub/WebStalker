import requests
import urllib3
import os
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS  = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
TIMEOUT  = 10

DEFAULT_WORDLIST   = "/usr/share/dirb/wordlists/common.txt"
SENSITIVE_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "wordlists", "sensitive.txt")

# Status codes displayed by default
DEFAULT_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}

# Color codes for terminal output
_C = {
    200: "\033[92m",  # green
    201: "\033[92m",
    204: "\033[92m",
    301: "\033[94m",  # blue
    302: "\033[94m",
    307: "\033[94m",
    401: "\033[93m",  # yellow
    403: "\033[93m",
    405: "\033[93m",
    500: "\033[91m",  # red
}
_RESET = "\033[0m"


# ─────────────────────────────────────────────
#  DIR / FILE FUZZER
# ─────────────────────────────────────────────

def dir_fuzzer(
    target: str,
    wordlist: str = DEFAULT_WORDLIST,
    extensions: list | None = None,
    threads: int = 20,
    show_codes: set | None = None,
    verbose: bool = True,
) -> dict:
    """
    Brute-force directories and files on a web target.

    Args:
        target:      Base URL (e.g. 'https://example.com')
        wordlist:    Path to wordlist file (one entry per line)
        extensions:  Extra extensions to append (e.g. ['.php', '.bak'])
        threads:     Number of concurrent threads (default: 20)
        show_codes:  HTTP status codes to display (default: DEFAULT_CODES)
        verbose:     Print findings in real time

    Returns dict with all findings.
    """
    target     = _normalize_url(target)
    show_codes = show_codes or DEFAULT_CODES
    extensions = extensions or []

    result = {
        "target":   target,
        "wordlist": wordlist,
        "findings": [],
        "total":    0,
        "error":    None,
    }

    words = _load_wordlist(wordlist)
    if words is None:
        result["error"] = f"Wordlist not found: {wordlist}"
        _print_fuzzer_header(result)
        return result

    # Build full list of paths to probe
    paths = []
    for word in words:
        word = word.strip().lstrip("/")
        if not word or word.startswith("#"):
            continue
        paths.append(word)
        for ext in extensions:
            ext = ext if ext.startswith(".") else f".{ext}"
            paths.append(f"{word}{ext}")

    session = requests.Session()
    session.headers.update(HEADERS)

    # Wildcard / catch-all detection
    baseline = _detect_wildcard(session, target)

    if verbose:
        _print_fuzzer_header(result, total_paths=len(paths), baseline=baseline)

    def probe(path: str):
        url = f"{target}/{path}"
        try:
            r = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
            hit = {
                "url":      url,
                "path":     f"/{path}",
                "code":     r.status_code,
                "size":     len(r.content),
                "redirect": r.headers.get("Location", ""),
            }
            # Filter out wildcard responses
            if baseline and _is_wildcard_response(hit, baseline, path):
                return None
            return hit
        except requests.RequestException:
            return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(probe, p): p for p in paths}
        for future in as_completed(futures):
            hit = future.result()
            if hit and hit["code"] in show_codes:
                result["findings"].append(hit)
                if verbose:
                    _print_finding(hit)

    result["findings"].sort(key=lambda x: x["code"])
    result["total"] = len(result["findings"])

    if verbose:
        print(f"\n  [{result['total']} result(s) found]\n")

    return result


# ─────────────────────────────────────────────
#  SENSITIVE FILE FINDER
# ─────────────────────────────────────────────

def sensitive_finder(
    target: str,
    wordlist: str = SENSITIVE_WORDLIST,
    threads: int = 20,
    show_codes: set | None = None,
    verbose: bool = True,
) -> dict:
    """
    Check for exposed sensitive files (.env, .git, backups, config files...).
    Uses the built-in wordlists/sensitive.txt by default.
    """
    return dir_fuzzer(
        target=target,
        wordlist=wordlist,
        extensions=[],
        threads=threads,
        show_codes=show_codes or {200, 201, 301, 302, 403},
        verbose=verbose,
    )


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def _random_path(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _detect_wildcard(session: requests.Session, target: str) -> dict | None:
    """
    Send 2 requests to random non-existent paths.
    If both return the same code and similar redirect pattern → catch-all detected.
    Returns a baseline dict or None if no wildcard.
    """
    probes = []
    for _ in range(2):
        path = _random_path()
        url  = f"{target}/{path}"
        try:
            # Same settings as probe() — no redirect following
            r = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
            probes.append({
                "code":     r.status_code,
                "size":     len(r.content),
                "redirect": r.headers.get("Location", ""),
                "path":     path,
            })
        except requests.RequestException:
            return None

    if len(probes) < 2:
        return None

    # Same code on both random paths → catch-all
    if probes[0]["code"] == probes[1]["code"]:
        # Check if redirect contains the path (pattern: target/{any_path})
        redirect_is_dynamic = (
            probes[0]["path"] in probes[0]["redirect"] and
            probes[1]["path"] in probes[1]["redirect"]
        )
        return {
            "code":              probes[0]["code"],
            "size":              probes[0]["size"],
            "redirect_dynamic":  redirect_is_dynamic,
            "redirect_prefix":   probes[0]["redirect"].replace(probes[0]["path"], "") if redirect_is_dynamic else "",
        }
    return None


def _is_wildcard_response(hit: dict, baseline: dict, path: str) -> bool:
    """Return True if the hit matches the wildcard baseline (should be filtered out)."""
    if hit["code"] != baseline["code"]:
        return False
    # Dynamic redirect: same prefix + current path → wildcard
    if baseline["redirect_dynamic"]:
        expected = baseline["redirect_prefix"] + path
        if hit["redirect"].rstrip("/") == expected.rstrip("/"):
            return True
    # Same code and same size → wildcard
    if abs(hit["size"] - baseline["size"]) <= 10:
        return True
    return False


def _normalize_url(target: str) -> str:
    target = target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    return target


def _load_wordlist(path: str) -> list | None:
    path = os.path.normpath(path)
    if not os.path.isfile(path):
        return None
    with open(path, "r", errors="ignore") as f:
        return f.readlines()


def _print_fuzzer_header(result: dict, total_paths: int = 0, baseline: dict | None = None):
    print(f"\n{'='*60}")
    print(f"  Dir/File Fuzzer — {result['target']}")
    print(f"  Wordlist : {result['wordlist']}")
    if total_paths:
        print(f"  Paths    : {total_paths}")
    if baseline:
        print(f"  \033[93m[!] Catch-all detected (HTTP {baseline['code']}) — wildcard responses filtered\033[0m")
    print(f"{'='*60}")
    if result["error"]:
        print(f"  [!] {result['error']}")
        return
    print(f"  {'CODE':<6} {'SIZE':<10} PATH")
    print(f"  {'-'*55}")


def _print_finding(hit: dict):
    code    = hit["code"]
    color   = _C.get(code, "")
    size    = f"{hit['size']} B"
    redirect = f"  →  {hit['redirect']}" if hit["redirect"] else ""
    print(f"  {color}[{code}]{_RESET}  {size:<10} {hit['path']}{redirect}")
