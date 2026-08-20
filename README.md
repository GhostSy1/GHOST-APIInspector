# GHOST-APIInspector

> Developed by Abdulaziz (Ghost-SY1). Authorized Professional API Security, SSRF, IDOR/BOLA & BFLA Analyzer.

---

## Overview & Purpose
**GHOST-APIInspector** is an enterprise-grade API security testing tool designed for authorized penetration testing, bug bounty assessments (e.g., HackenProof), and CI/CD security pipelines. It performs non-destructive endpoint discovery, authorized Server-Side Request Forgery (SSRF) testing, Broken Object Level Authorization (IDOR/BOLA) validation, and Function-Level Authorization (BFLA) checks using multi-privilege session tokens.

---

## Key Features
- **Endpoint Enumeration**: Discovers active API paths (`/api/v1`, `/swagger.json`, `/openapi.json`, `/graphql`).
- **Authorized SSRF Inspector**: Safely tests external URL fetching parameters against user-owned OAST callbacks.
- **IDOR / BOLA Validator**: Compares resource access across two distinct user tokens (`--token-a` and `--token-b`).
- **BFLA (Function-Level Authorization) Validator**: Tests whether low-privileged tokens can access administrative functions (`--bfla-url` and `--low-priv-token`).
- **SQLi & XSS Canary Testing**: Low-impact reflection and error-based indicator analysis (`--scan-vulns`).
- **Zero Mock Data**: Strictly outputs telemetry derived from real HTTP exchanges and active socket probes.

---

## Usage & Command Line Reference

```bash
python3 main.py --target https://api.target.com --bfla-url https://api.target.com/admin/settings --low-priv-token TOKEN_USER_REGULAR --json report.json
```

| Argument | Description | Default |
|---|---|---|
| `--target` | Target API Base URL | Interactive prompt |
| `--callback` | Authorized SSRF callback URL | None |
| `--idor-url` | Specific endpoint for IDOR/BOLA comparison | None |
| `--token-a` / `--token-b` | Auth tokens for IDOR comparison | None |
| `--bfla-url` | Privileged admin endpoint for BFLA testing | None |
| `--low-priv-token` | Low-privilege token for BFLA testing | None |
| `--scan-vulns` | Enable authorized SQLi/XSS canary checks | False |
| `--json` | Output JSON report path | `api_report.json` |

---
**License**: MIT / Proprietary Operational Use.
