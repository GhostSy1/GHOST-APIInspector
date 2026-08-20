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
    GHOST-APIInspector: Authorized API, SSRF, IDOR, SQLi, XSS & BFLA Inspector (v3.4-PRO)
""")

def inspect_api(target_url, callback_url=None, test_endpoint=None, token_a=None, token_b=None, scan_vulnerabilities=False, bfla_endpoint=None, low_priv_token=None):
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    common_api_paths = ["/api/v1", "/swagger.json", "/openapi.json", "/v1/health", "/graphql", "/auth/login"]
    base_url = target_url.rstrip("/")

    for path in common_api_paths:
        url = base_url + path
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Ghost-APIInspector/3.4'})
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
            req = urllib.request.Request(ssrf_test_url, headers={'User-Agent': 'Ghost-APIInspector/3.4-SSRF-Test'})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                findings.append({
                    "ssrf_probe_endpoint": ssrf_test_url,
                    "status": resp.getcode(),
                    "vulnerable_indicator": "Endpoint accepted external URL parameter for server-side fetching"
                })
        except Exception as e:
            findings.append({"ssrf_probe_endpoint": ssrf_test_url, "error": str(e)})

    # Safe Authorized IDOR / BOLA Inspection
    if test_endpoint and token_a and token_b:
        print(f"[+] Performing authorized IDOR / BOLA access control test on: {test_endpoint}")
        try:
            req_a = urllib.request.Request(test_endpoint, headers={'Authorization': f'Bearer {token_a}', 'User-Agent': 'Ghost-APIInspector/3.4-IDOR'})
            resp_a = urllib.request.urlopen(req_a, timeout=5, context=ctx)
            code_a = resp_a.getcode()
            body_a = resp_a.read().decode('utf-8', errors='ignore')
            
            req_b = urllib.request.Request(test_endpoint, headers={'Authorization': f'Bearer {token_b}', 'User-Agent': 'Ghost-APIInspector/3.4-IDOR'})
            resp_b = urllib.request.urlopen(req_b, timeout=5, context=ctx)
            code_b = resp_b.getcode()
            body_b = resp_b.read().decode('utf-8', errors='ignore')

            bola_risk = (code_a == 200 and code_b == 200 and body_a == body_b)
            findings.append({
                "idor_test_endpoint": test_endpoint,
                "user_a_status": code_a,
                "user_b_status": code_b,
                "bola_potential_vulnerability": bola_risk
            })
        except Exception as e:
            findings.append({"idor_test_endpoint": test_endpoint, "error": str(e)})

    # Safe Authorized BFLA (Function-Level Authorization) Inspection
    if bfla_endpoint and low_priv_token:
        print(f"[+] Performing authorized BFLA (Function-Level Authorization) test on privileged function: {bfla_endpoint}")
        try:
            req_bfla = urllib.request.Request(bfla_endpoint, headers={'Authorization': f'Bearer {low_priv_token}', 'User-Agent': 'Ghost-APIInspector/3.4-BFLA'})
            resp_bfla = urllib.request.urlopen(req_bfla, timeout=5, context=ctx)
            code_bfla = resp_bfla.getcode()
            bfla_risk = (code_bfla == 200 or code_bfla == 201)
            findings.append({
                "bfla_test_endpoint": bfla_endpoint,
                "low_priv_status_code": code_bfla,
                "bfla_potential_vulnerability": bfla_risk,
                "note": "Low-privileged user accessed privileged administrative function successfully." if bfla_risk else "Function properly protected."
            })
        except urllib.error.HTTPError as e:
            findings.append({
                "bfla_test_endpoint": bfla_endpoint,
                "low_priv_status_code": e.code,
                "bfla_potential_vulnerability": False,
                "note": "Endpoint correctly blocked low-privileged user."
            })
        except Exception as e:
            findings.append({"bfla_test_endpoint": bfla_endpoint, "error": str(e)})

    # Safe Authorized SQLi & XSS Canary Inspection
    if scan_vulnerabilities:
        print("[+] Performing authorized low-impact SQLi and XSS canary reflection analysis...")
        sqli_canary = "'+OR+'1'='1"
        xss_canary = "<script>console.log('GHOST-CANARY')</script>"
        
        test_canary_url = f"{base_url}/api/v1/search?q={urllib.parse.quote(sqli_canary)}"
        try:
            req = urllib.request.Request(test_canary_url, headers={'User-Agent': 'Ghost-APIInspector/3.4-SQLi'})
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            body = resp.read().decode('utf-8', errors='ignore').lower()
            sqli_indic = any(err in body for err in ["sql syntax", "mysql", "syntax error", "ora-", "sqlite3"])
            findings.append({
                "vulnerability_type": "SQL Injection (Error-based/Canary)",
                "test_url": test_canary_url,
                "potential_indicator_found": sqli_indic
            })
        except Exception:
            pass

        test_xss_url = f"{base_url}/api/v1/search?q={urllib.parse.quote(xss_canary)}"
        try:
            req = urllib.request.Request(test_xss_url, headers={'User-Agent': 'Ghost-APIInspector/3.4-XSS'})
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            body = resp.read().decode('utf-8', errors='ignore')
            xss_indic = xss_canary in body
            findings.append({
                "vulnerability_type": "Reflected XSS (Canary Reflection)",
                "test_url": test_xss_url,
                "reflected": xss_indic
            })
        except Exception:
            pass

    return findings

def main():
    banner()
    parser = argparse.ArgumentParser(description="GHOST-APIInspector Enterprise Engine with SSRF, IDOR, SQLi, XSS & BFLA Detection")
    parser.add_argument("--target", help="Target API Base URL")
    parser.add_argument("--callback", help="Authorized SSRF callback URL")
    parser.add_argument("--idor-url", help="Specific resource endpoint to test IDOR/BOLA")
    parser.add_argument("--token-a", help="Auth token for User A")
    parser.add_argument("--token-b", help="Auth token for User B")
    parser.add_argument("--bfla-url", help="Privileged administrative endpoint to test BFLA")
    parser.add_argument("--low-priv-token", help="Low-privileged auth token for BFLA testing")
    parser.add_argument("--scan-vulns", action="store_true", help="Enable authorized SQLi and XSS canary testing")
    parser.add_argument("--json", help="Output JSON report path", default="api_report.json")
    args, unknown = parser.parse_known_args()

    target = args.target
    if not target:
        target = input("[*] Enter Target API Base URL: ").strip()

    print(f"\n[+] Probing API endpoints against: {target}")
    findings = inspect_api(target, callback_url=args.callback, test_endpoint=args.idor_url, token_a=args.token_a, token_b=args.token_b, scan_vulnerabilities=args.scan_vulns, bfla_endpoint=args.bfla_url, low_priv_token=args.low_priv_token)

    report = {
        "target": target,
        "engine": "GHOST-APIInspector v3.4-PRO",
        "endpoints_analyzed": len(findings),
        "findings": findings
    }

    with open(args.json, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] API Inspector report saved to: {args.json}")

if __name__ == "__main__":
    main()
