# GHOST-APIInspector

> Authorized API security assessment utility for controlled environments, developed by Abdulaziz (Ghost-SY1).

## Purpose

GHOST-APIInspector performs live, non-destructive API observations and authorization checks against a target that the operator owns or is explicitly authorized to assess. Its checks cover endpoint discovery, SSRF, BOLA/IDOR, BFLA, Mass Assignment, and Excessive Data Exposure (oversharing).

## Excessive Data Exposure operation

The `--exposure-url` option inspects JSON responses for sensitive or undocumented field names (such as passwords, tokens, internal IDs, or auth keys) without printing or logging their values.

```bash
python3 main.py \
  --target https://staging.example.test \
  --exposure-url https://staging.example.test/api/v1/user/profile \
  --exposure-token "$USER_TOKEN_A" \
  --json exposure-report.json
```

A discovered sensitive field is an observational triage signal. Analysts must confirm whether the endpoint intentionally exposes those attributes to the given privilege level.

## Local verification

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

---
**License**: MIT / Proprietary Operational Use.

## Engineering and release baseline

This repository is maintained as part of the Ghost-SY1 security engineering portfolio. The project is intended for authorized assessment, analysis, or defensive engineering, according to the concrete behavior implemented in the source tree. Results must be derived from operator-supplied inputs and should be reviewed against the documented limitations before they are used in a decision.

### Repository map

| Path | Purpose |
|---|---|
| `README.md` | Installation, usage, scope, and limitations |
| `docs/` | Detailed operational and architectural documentation |
| `tests/` | Reproducible checks for implemented behavior |
| `.github/workflows/` | Automated quality and release checks |
| `SECURITY.md` | Vulnerability reporting and release hygiene |
| `CONTRIBUTING.md` | Contribution and review requirements |

### Verification

Run the repository-specific command documented above, then run the checks in `.github/workflows/quality.yml` locally where the required runtime is available. Do not interpret a passing syntax check as proof that every deployment or security decision is correct.

### Responsible use

Use only with explicit authorization. Do not commit credentials, private keys, customer data, or raw engagement artifacts. The repository does not provide a guarantee that an observation is a vulnerability; analysts must preserve evidence and validate conclusions independently.
