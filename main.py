import os
import sys
import argparse
import json
import urllib.request
import urllib.parse
import ssl

def banner():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    print(r"""
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     █████╗ ██████╗ ██╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██║
 ██║  ███╗███████║██║   ██║███████╗   ██║       ███████║██████╔╝██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██╔══██║██╔═══╝ ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║  ██║██║     ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝     ╚═╝
    GHOST-APIInspector: Authorized API Endpoint & Schema Security Analyzer
""")

def inspect_api(target_url):
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    common_api_paths = ["/api/v1", "/swagger.json", "/openapi.json", "/v1/health", "/graphql", "/auth/login"]
    base_url = target_url.rstrip("/")

    for path in common_api_paths:
        url = base_url + path
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Ghost-APIInspector/3.0'})
            with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
                findings.append({
                    "endpoint": url,
                    "status": resp.getcode(),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "active": True
                })
        except urllib.error.HTTPError as e:
            findings.append({
                "endpoint": url,
                "status": e.code,
                "active": True,
                "note": "Endpoint responded with HTTP error code"
            })
        except Exception:
            pass
    return findings

def main():
    banner()
    parser = argparse.ArgumentParser(description="GHOST-APIInspector Enterprise Engine")
    parser.add_argument("--target", help="Target API Base URL (e.g. https://api.target.com)")
    parser.add_argument("--json", help="Output JSON report path", default="api_report.json")
    args, unknown = parser.parse_known_args()

    target = args.target
    if not target:
        target = input("[*] Enter Target API Base URL: ").strip()

    print(f"\n[+] Probing API endpoints against: {target}")
    findings = inspect_api(target)

    report = {
        "target": target,
        "engine": "GHOST-APIInspector v3.0-PRO",
        "endpoints_analyzed": len(findings),
        "findings": findings
    }

    with open(args.json, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] API Inspector report saved to: {args.json}")

if __name__ == "__main__":
    main()
