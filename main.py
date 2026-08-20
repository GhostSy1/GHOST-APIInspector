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
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     █████╗ ██████╗  ██╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗ ██║
 ██║  ███╗███████║██║   ██║███████╗   ██║       ███████║██████╔╝ ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██╔══██║██╔═══╝  ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║  ██║██║      ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝      ╚═╝
    GHOST-APIInspector: Authorized API, SSRF & IDOR/BOLA Inspector (v3.2-PRO)
""")

def inspect_api(target_url, callback_url=None, test_endpoint=None, token_a=None, token_b=None):
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    common_api_paths = ["/api/v1", "/swagger.json", "/openapi.json", "/v1/health", "/graphql", "/auth/login"]
    base_url = target_url.rstrip("/")

    for path in common_api_paths:
        url = base_url + path
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Ghost-APIInspector/3.2'})
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

    # Safe Authorized SSRF Inspection
    if callback_url:
        print(f"[+] Performing authorized SSRF parameter injection test using callback: {callback_url}")
        ssrf_test_url = f"{base_url}/api/v1/fetch?url={urllib.parse.quote(callback_url)}"
        try:
            req = urllib.request.Request(ssrf_test_url, headers={'User-Agent': 'Ghost-APIInspector/3.2-SSRF-Test'})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                findings.append({
                    "ssrf_probe_endpoint": ssrf_test_url,
                    "status": resp.getcode(),
                    "vulnerable_indicator": "Endpoint accepted external URL parameter for server-side fetching"
                })
        except urllib.error.HTTPError as e:
            findings.append({
                "ssrf_probe_endpoint": ssrf_test_url,
                "status": e.code,
                "note": "SSRF probe returned HTTP error"
            })
        except Exception as e:
            findings.append({
                "ssrf_probe_endpoint": ssrf_test_url,
                "error": str(e)
            })

    # Safe Authorized IDOR / BOLA Inspection
    if test_endpoint and token_a and token_b:
        print(f"[+] Performing authorized IDOR / BOLA access control test on: {test_endpoint}")
        try:
            # Request with Token A
            req_a = urllib.request.Request(test_endpoint, headers={'Authorization': f'Bearer {token_a}', 'User-Agent': 'Ghost-APIInspector/3.2-IDOR-Test'})
            resp_a = urllib.urlopen(req_a, timeout=5, context=ctx) if hasattr(urllib, 'urlopen') else urllib.request.urlopen(req_a, timeout=5, context=ctx)
            code_a = resp_a.getcode()
            body_a = resp_a.read().decode('utf-8', errors='ignore')
            
            # Request with Token B (different user/context)
            req_b = urllib.request.Request(test_endpoint, headers={'Authorization': f'Bearer {token_b}', 'User-Agent': 'Ghost-APIInspector/3.2-IDOR-Test'})
            resp_b = urllib.request.urlopen(req_b, timeout=5, context=ctx)
            code_b = resp_b.getcode()
            body_b = resp_b.read().decode('utf-8', errors='ignore')

            bola_risk = False
            if code_a == 200 and code_b == 200 and len(body_b) > 10 and body_a == body_b:
                bola_risk = True

            findings.append({
                "idor_test_endpoint": test_endpoint,
                "user_a_status": code_a,
                "user_b_status": code_b,
                "bola_potential_vulnerability": bola_risk,
                "note": "Both users received identical resources; check authorization logic if resource should be private."
            })
        except Exception as e:
            findings.append({
                "idor_test_endpoint": test_endpoint,
                "error": str(e)
            })

    return findings

def main():
    banner()
    parser = argparse.ArgumentParser(description="GHOST-APIInspector Enterprise Engine with SSRF & IDOR Detection")
    parser.add_argument("--target", help="Target API Base URL (e.g. https://api.target.com)")
    parser.add_argument("--callback", help="Authorized OAST / SSRF callback URL")
    parser.add_argument("--idor-url", help="Specific resource endpoint to test IDOR/BOLA")
    parser.add_argument("--token-a", help="Auth token or API key for User A")
    parser.add_argument("--token-b", help="Auth token or API key for User B")
    parser.add_argument("--json", help="Output JSON report path", default="api_report.json")
    args, unknown = parser.parse_known_args()

    target = args.target
    if not target:
        target = input("[*] Enter Target API Base URL: ").strip()

    print(f"\n[+] Probing API endpoints against: {target}")
    findings = inspect_api(target, callback_url=args.callback, test_endpoint=args.idor_url, token_a=args.token_a, token_b=args.token_b)

    report = {
        "target": target,
        "engine": "GHOST-APIInspector v3.2-PRO",
        "endpoints_analyzed": len(findings),
        "findings": findings
    }

    with open(args.json, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] API Inspector report saved to: {args.json}")

if __name__ == "__main__":
    main()
