# GHOST-APIInspector

> Developed by Abdulaziz (Ghost-SY1). Authorized Professional API Security, SSRF, IDOR/BOLA & BFLA Analyzer.

---

## Overview & Purpose
**GHOST-APIInspector** is an enterprise-grade API security testing tool designed for authorized penetration testing, bug bounty assessments (e.g., HackenProof), and CI/CD security pipelines. It performs non-destructive endpoint discovery, authorized Server-Side Request Forgery (SSRF) testing, Broken Object Level Authorization (IDOR/BOLA) validation, and Function-Level Authorization (BFLA) checks.

---

## Key Features
- **Endpoint Enumeration**: Discovers active API paths (`/api/v1`, `/swagger.json`, `/openapi.json`, `/graphql`).
- **Authorized SSRF Inspector**: Safely tests external URL fetching parameters against user-owned OAST callbacks.
- **IDOR / BOLA Validator**: Compares resource access across two distinct user tokens (`--token-a` and `--token-b`).
- **BFLA Validator**: Tests whether low-privileged tokens can access administrative functions (`--bfla-url` and `--low-priv-token`).
- **Unit Testing**: Fully validated logic through automated unit tests (`tests/test_api.py`).

---

## Running Unit Tests Locally
To verify the BFLA, IDOR, and core logic locally:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

---

## CI/CD Pipeline Setup & Secrets Configuration
To integrate GHOST-APIInspector into your GitHub Actions pipeline:
1. Go to your repository **Settings > Secrets and variables > Actions**.
2. Add the following optional repository secrets for live staging verification:
   - `STAGING_API_URL`: Base URL of your authorized staging API.
   - `USER_TOKEN_A`: Session token for User Context A.
   - `USER_TOKEN_B`: Session token for User Context B.
3. The workflow in `.github/workflows/api_inspector_ci.yml` will automatically run unit tests on every Pull Request and execute safe authorized checks on pushes to `main`.

---
**License**: MIT / Proprietary Operational Use.
