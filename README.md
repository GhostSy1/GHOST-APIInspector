# GHOST-APIInspector

> Developed by Abdulaziz (Ghost-SY1). Authorized Professional API Security, SSRF, IDOR/BOLA, BFLA & Mass Assignment Analyzer.

---

## Overview & Purpose
**GHOST-APIInspector** is an enterprise-grade API security testing tool designed for authorized penetration testing, bug bounty assessments (e.g., HackenProof), and CI/CD security pipelines. It performs non-destructive endpoint discovery, authorized Server-Side Request Forgery (SSRF) testing, Broken Object Level Authorization (IDOR/BOLA) validation, Function-Level Authorization (BFLA) checks, and Mass Assignment (Mass Binding) vulnerability detection using session tokens.

---

## Key Features
- **Endpoint Enumeration**: Discovers active API paths (`/api/v1`, `/swagger.json`, `/openapi.json`, `/graphql`).
- **Authorized SSRF Inspector**: Safely tests external URL fetching parameters against user-owned OAST callbacks.
- **IDOR / BOLA Validator**: Compares resource access across two distinct user tokens (`--token-a` and `--token-b`).
- **BFLA Validator**: Tests whether low-privileged tokens can access administrative functions (`--bfla-url` and `--low-priv-token`).
- **Mass Assignment Inspector**: Tests if PUT/PATCH endpoints accept unbindable privileged properties (`--mass-url` and `--mass-token`).
- **SQLi & XSS Canary Testing**: Low-impact reflection and error-based indicator analysis (`--scan-vulns`).

---

## How to Analyze JSON Reports
When you run GHOST-APIInspector, it outputs a JSON report (e.g., `api_report.json`). 
1. **Raw Evidence vs. Verified Finding**: A finding like `bola_potential_vulnerability: true` or `mass_assignment_potential_vulnerability: true` is an **observational triage signal**, not a definitive vulnerability proof.
2. **Reviewing Status Codes**: If User A and User B both get HTTP 200 with identical bodies on an object endpoint, verify whether that object is intended to be public.
3. **Mass Assignment Verification**: If an endpoint accepts `role: admin` or `is_admin: true` in a PUT request without rejection, manually verify if the database state actually changed.

---
**License**: MIT / Proprietary Operational Use.
