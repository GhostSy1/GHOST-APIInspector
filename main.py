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
    GHOST-APIInspector: Authorized API, SSRF, IDOR, SQLi, XSS, BFLA & Mass Assignment (v3.5-PRO)
""")

def inspect_api(target_url, callback_url=None, test_endpoint=None, token_a=None, token_b=None, scan_vulnerabilities=False, bfla_endpoint=None, low_priv_token=None, mass_endpoint=None, mass_token=None):
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    common_api_paths = ["/api/v1", "/swagger.json", "/openapi.json", "/v1/health", "/graphql", "/auth/login"]
    base_url = target_url.rstrip("/")

    for path in common_api_paths:
        url = base_url + path
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Ghost-APIInspector/3.5'})
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
            req = urllib.request.Request(ssrf_test_url, headers={'User-Agent': 'Ghost-APIInspector/3.5-SSRF-Test'})
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
            req_a = urllib.request.Request(test_endpoint, headers={'Authorization': f'Bearer {token_a}', 'User-Agent': 'Ghost-APIInspector/3.5-IDOR'})
            resp_a = urllib.request.urlopen(req_a, timeout=5, context=ctx)
            code_a = resp_a.getcode()
            body_a = resp_a.read().decode('utf-8', errors='ignore')
            
            req_b = urllib.request.Request(test_endpoint, headers={'Authorization': f'Bearer {token_b}', 'User-Agent': 'Ghost-APIInspector/3.5-IDOR'})
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

    # Safe Authorized BFLA Inspection
    if bfla_endpoint and low_priv_token:
        print(f"[+] Performing authorized BFLA test on privileged function: {bfla_endpoint}")
        try:
            req_bfla = urllib.request.Request(bfla_endpoint, headers={'Authorization': f'Bearer {low_priv_token}', 'User-Agent': 'Ghost-APIInspector/3.5-BFLA'})
            resp_bfla = urllib.request.urlopen(req_bfla, timeout=5, context=ctx)
            code_bfla = resp_bfla.getcode()
            bfla_risk = (code_bfla in {200, 201})
            findings.append({
                "bfla_test_endpoint": bfla_endpoint,
                "low_priv_status_code": code_bfla,
                "bfla_potential_vulnerability": bfla_risk
            })
        except urllib.error.HTTPError as e:
            findings.append({"bfla_test_endpoint": bfla_endpoint, "low_priv_status_code": e.code, "bfla_potential_vulnerability": False})
        except Exception as e:
            findings.append({"bfla_test_endpoint": bfla_endpoint, "error": str(e)})

    # Safe Authorized Mass Assignment Inspection
    if mass_endpoint and mass_token:
        print(f"[+] Performing authorized Mass Assignment parameter injection check on: {mass_endpoint}")
        try:
            payload = json.dumps({"role": "admin", "is_admin": True, "balance": 999999, "permissions": ["all"]}).encode("utf-8")
            req_mass = urllib.request.Request(
                mass_endpoint,
                data=payload,
                headers={
                    'Authorization': f'Bearer {mass_token}',
                    'Content-Type': 'application/json',
                    'User-Agent': 'Ghost-APIInspector/3.5-MassAssignment'
                },
                method='PUT'
            )
            resp_mass = urllib.request.urlopen(req_mass, timeout=5, context=ctx)
            code_mass = resp_mass.getcode()
            body_mass = resp_mass.read().decode('utf-8', errors='ignore').lower()
            
            mass_risk = (code_mass in {200, 201, 202} and any(k in body_mass for k in ["admin", "role", "permissions"]))
            findings.append({
                "mass_assignment_endpoint": mass_endpoint,
                "status_code": code_mass,
                "mass_assignment_potential_vulnerability": mass_risk,
                "note": "Endpoint accepted privileged JSON properties in update payload without rejection." if mass_risk else "Endpoint rejected or ignored extra parameters."
            })
        except urllib.error.HTTPError as e:
            findings.append({
                "mass_assignment_endpoint": mass_endpoint,
                "status_code": e.code,
                "mass_assignment_potential_vulnerability": False,
                "note": "Endpoint rejected privileged property update."
            })
        except Exception as e:
            findings.append({"mass_assignment_endpoint": mass_endpoint, "error": str(e)})

    # Safe Authorized SQLi & XSS Canary Inspection
    if scan_vulnerabilities:
        print("[+] Performing authorized low-impact SQLi and XSS canary reflection analysis...")
        sqli_canary = "'+OR+'1'='1"
        xss_canary = "<script>console.log('GHOST-CANARY')</script>"
        
        test_canary_url = f"{base_url}/api/v1/search?q={urllib.parse.quote(sqli_canary)}"
        try:
            req = urllib.request.Request(test_canary_url, headers={'User-Agent': 'Ghost-APIInspector/3.5-SQLi'})
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
            req = urllib.request.Request(test_xss_url, headers={'User-Agent': 'Ghost-APIInspector/3.5-XSS'})
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
    parser = argparse.ArgumentParser(description="GHOST-APIInspector Enterprise Engine with SSRF, IDOR, SQLi, XSS, BFLA & Mass Assignment Detection")
    parser.add_argument("--target", help="Target API Base URL")
    parser.add_argument("--callback", help="Authorized SSRF callback URL")
    parser.add_argument("--idor-url", help="Specific resource endpoint to test IDOR/BOLA")
    parser.add_argument("--token-a", help="Auth token for User A")
    parser.add_argument("--token-b", help="Auth token for User B")
    parser.add_argument("--bfla-url", help="Privileged administrative endpoint to test BFLA")
    parser.add_argument("--low-priv-token", help="Low-privileged auth token for BFLA testing")
    parser.add_argument("--mass-url", help="Endpoint to test Mass Assignment (e.g. PUT /api/v1/profile)")
    parser.add_argument("--mass-token", help="Auth token for Mass Assignment testing")
    parser.add_argument("--scan-vulns", action="store_true", help="Enable authorized SQLi and XSS canary testing")
    parser.add_argument("--json", help="Output JSON report path", default="api_report.json")
    args, unknown = parser.parse_known_args()

    token_a = args.token_a or os.getenv("GHOST_TOKEN_A")
    token_b = args.token_b or os.getenv("GHOST_TOKEN_B")
    low_priv_token = args.low_priv_token or os.getenv("GHOST_LOW_PRIV_TOKEN")
    mass_token = args.mass_token or os.getenv("GHOST_MASS_TOKEN")

    target = args.target
    if not target:
        target = input("[*] Enter Target API Base URL: ").strip()

    print(f"\n[+] Probing API endpoints against: {target}")
    findings = inspect_api(
        target,
        callback_url=args.callback,
        test_endpoint=args.idor_url,
        token_a=token_a,
        token_b=token_b,
        scan_vulnerabilities=args.scan_vulns,
        bfla_endpoint=args.bfla_url,
        low_priv_token=low_priv_token,
        mass_endpoint=args.mass_url,
        mass_token=mass_token
    )

    report = {
        "target": target,
        "engine": "GHOST-APIInspector v3.5-PRO",
        "endpoints_analyzed": len(findings),
        "findings": findings
    }

    with open(args.json, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] API Inspector report saved to: {args.json}")

if __name__ == "__main__":
    main()
