# GHOST-APIInspector

> Developed by Abdulaziz (Ghost-SY1). Authorized Professional API Security, SSRF & IDOR/BOLA Analyzer.

---

## Overview & Purpose
**GHOST-APIInspector** is an enterprise-grade API security testing tool designed for authorized penetration testing, bug bounty assessments (e.g., HackenProof), and CI/CD security pipelines. It performs non-destructive endpoint discovery, authorized Server-Side Request Forgery (SSRF) testing, and Broken Object Level Authorization (IDOR/BOLA) validation using multi-user session tokens.

---

## Key Features
- **Endpoint Enumeration**: Discovers active API paths (`/api/v1`, `/swagger.json`, `/openapi.json`, `/graphql`).
- **Authorized SSRF Inspector**: Safely tests external URL fetching parameters against user-owned OAST callbacks (e.g., Burp Collaborator).
- **IDOR / BOLA Validator**: Compares resource access responses across two distinct user tokens (`--token-a` and `--token-b`) to spot authorization flaws.
- **Zero Mock Data**: Strictly outputs telemetry derived from real HTTP exchanges and active socket probes.

---

## Installation & Setup

```bash
git clone https://github.com/GhostSy1/GHOST-APIInspector.git
cd GHOST-APIInspector
python3 -m pip install --upgrade pip
```

---

## Usage & Command Line Reference

```bash
python3 main.py --target https://api.target.com --callback https://your-callback.com --idor-url https://api.target.com/v1/user/101 --token-a TOKEN_USER_1 --token-b TOKEN_USER_2 --json report.json
```

| Argument | Description | Default |
|---|---|---|
| `--target` | Target API Base URL | Interactive prompt |
| `--callback` | Authorized SSRF callback URL | None |
| `--idor-url` | Specific endpoint for IDOR/BOLA comparison | None |
| `--token-a` | Auth token for User Context A | None |
| `--token-b` | Auth token for User Context B | None |
| `--json` | Output JSON report path | `api_report.json` |

---

## CI/CD Pipeline Integration
You can integrate GHOST-APIInspector into GitHub Actions to automatically run API security checks against staging environments:

```yaml
name: GHOST-APIInspector CI/CD
on:
  push:
    branches: [ main ]
jobs:
  api-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - name: Run API Inspector
        run: |
          python3 main.py --target https://staging.api.target.com --json staging_report.json
```

---

## Legal & Compliance Notice
This tool is strictly intended for authorized security testing under written permission. Unauthorized use is prohibited.

---
**License**: MIT / Proprietary Operational Use.
