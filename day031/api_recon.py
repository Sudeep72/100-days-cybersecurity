"""
Day 031 - API Recon Tool
100 Days of Cybersecurity by Sudeep Ravichandran

Discovers API endpoints, tests authentication,
and probes for common vulnerabilities.

Usage: python3 api_recon.py <base-url>
Requires: pip install requests
"""

import requests
import json
import sys
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()

# Common API paths to probe
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/graphql",
    "/swagger", "/swagger-ui", "/swagger.json",
    "/api-docs", "/openapi.json", "/openapi.yaml",
    "/docs", "/internal", "/admin", "/api/admin",
    "/api/users", "/api/user", "/api/me",
    "/api/health", "/api/status", "/api/version",
    "/api/config", "/api/debug",
]

HEADERS_TO_TEST = [
    {},
    {"Authorization": "Bearer invalid"},
    {"X-API-Key": "test"},
    {"Authorization": "Bearer null"},
    {"X-Admin": "true"},
    {"X-Internal": "true"},
    {"X-Forwarded-For": "127.0.0.1"},
]


def probe_endpoints(base_url):
    print("\n[+] ENDPOINT DISCOVERY")
    print("-" * 45)
    found = []

    for path in API_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=5, verify=False,
                           allow_redirects=False)
            if r.status_code not in [404, 410]:
                content_type = r.headers.get("Content-Type", "")
                is_api = "json" in content_type or "xml" in content_type
                tag = "🎯 API" if is_api else "   "
                print(f"  {tag} [{r.status_code}] {url}")
                found.append((url, r.status_code))
        except requests.exceptions.RequestException:
            pass

    return found


def test_auth_bypass(base_url, endpoints):
    print("\n[+] AUTHENTICATION BYPASS TESTS")
    print("-" * 45)

    for url, status in endpoints[:5]:  # test first 5 found
        for headers in HEADERS_TO_TEST:
            try:
                r = requests.get(url, headers=headers,
                               timeout=5, verify=False)
                if r.status_code == 200:
                    header_str = str(headers) if headers else "no headers"
                    print(f"  ⚠  {url}")
                    print(f"     Auth header: {header_str}")
                    print(f"     Response: {r.status_code} "
                          f"({len(r.content)} bytes)")
                    # Show first 100 chars of response
                    try:
                        preview = r.json()
                        print(f"     Preview: {str(preview)[:100]}")
                    except Exception:
                        pass
                    break
            except requests.exceptions.RequestException:
                pass


def test_idor(base_url):
    print("\n[+] IDOR PROBE (numeric ID enumeration)")
    print("-" * 45)

    id_endpoints = [
        "/api/users/{id}",
        "/api/v1/users/{id}",
        "/api/orders/{id}",
        "/api/accounts/{id}",
    ]

    for template in id_endpoints:
        for i in range(1, 6):
            url = urljoin(base_url, template.format(id=i))
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code == 200:
                    print(f"  [+] {url} → {r.status_code} "
                          f"({len(r.content)} bytes)")
            except requests.exceptions.RequestException:
                pass


def check_swagger(base_url):
    print("\n[+] API DOCUMENTATION CHECK")
    print("-" * 45)

    doc_paths = [
        "/swagger.json", "/openapi.json",
        "/api-docs", "/swagger-ui/index.html"
    ]

    for path in doc_paths:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                print(f"  🎯 Documentation found: {url}")
                try:
                    spec = r.json()
                    paths = spec.get("paths", {})
                    print(f"     Endpoints documented: {len(paths)}")
                    for ep in list(paths.keys())[:10]:
                        print(f"     → {ep}")
                except Exception:
                    print(f"     (non-JSON documentation)")
        except requests.exceptions.RequestException:
            pass


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 api_recon.py <base-url>")
        print("Example: python3 api_recon.py https://target.com")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")

    print("=" * 50)
    print("  API Recon Tool - Day 031")
    print("  100 Days of Cybersecurity")
    print("=" * 50)
    print(f"  Target: {base_url}")
    print("  ⚠  Only use on systems you have permission to test")

    check_swagger(base_url)
    found = probe_endpoints(base_url)
    if found:
        test_auth_bypass(base_url, found)
    test_idor(base_url)

    print("\n" + "=" * 50)
    print("  Recon complete.")
    print("  Review findings - test manually in Burp Suite")
    print("=" * 50)


if __name__ == "__main__":
    main()