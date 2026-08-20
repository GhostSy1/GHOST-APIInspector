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
