# GHOST-APIInspector

> Authorized API security assessment utility for controlled environments, developed by Abdulaziz (Ghost-SY1).

## Purpose

GHOST-APIInspector performs live, non-destructive API observations and authorization checks against a target that the operator owns or is explicitly authorized to assess. Its access-control checks are designed for two distinct use cases. **BOLA/IDOR** compares access to one known resource under two approved test identities. **BFLA** checks whether a low-privilege test identity can reach a function that the engagement rules classify as privileged. The tool records HTTP evidence; it does not claim that a response alone is a final vulnerability proof.

The repository does not embed target responses, credentials, fabricated findings, or a list of “known vulnerable” endpoints. Discovery results come from the target URL supplied at runtime. The BFLA and BOLA checks are opt-in and require explicit test inputs.

## Security boundary

Use the tool only against an owned API, a written assessment scope, or a program that explicitly permits this class of testing. The CI workflow rejects staging hosts that are not in the configured allowlist. Never place access tokens in source files, README examples, command history, or ordinary repository variables. GitHub Actions receives them through encrypted secrets and the program reads them from the process environment without printing them.

The BFLA and BOLA modes are intended for safe authorization verification. They do not enumerate arbitrary object identifiers, brute-force roles, perform state-changing actions by default, bypass controls, or access internal services.

## Installation

The runtime has no third-party dependency for the core CLI:

```bash
git clone https://github.com/GhostSy1/GHOST-APIInspector.git
cd GHOST-APIInspector
python3 --version
python3 main.py --help
```

Python 3.10 or newer is recommended. The implementation uses the Python standard library for HTTP, TLS context handling, argument parsing, JSON reporting, and the local test server.

## BOLA/IDOR operation

BOLA/IDOR testing requires one known resource endpoint and two authorized test identities. Account A should be permitted to access the resource; account B should be a different approved identity that should not receive that resource. The tool sends the same read request with each bearer token and reports a **potential** signal only when both responses succeed and their non-empty bodies are identical.

```bash
python3 main.py \
  --target https://staging.example.test \
  --idor-url https://staging.example.test/api/orders/known-test-order \
  --token-a "$USER_TOKEN_A" \
  --token-b "$USER_TOKEN_B" \
  --json idor-report.json
```

An identical response is a triage signal, not a complete proof. Analysts must confirm resource ownership, response semantics, tenant boundaries, and whether the endpoint intentionally exposes the same public object.

## BFLA operation

BFLA concerns authorization at the function or operation level rather than ownership of one object. Provide a known administrative or otherwise privileged endpoint and a low-privilege test token. A `200` or `201` response is recorded as a potential BFLA signal; `401` or `403` is recorded as a blocked access result. The test should use a safe read-only administrative endpoint whenever possible.

```bash
python3 main.py \
  --target https://staging.example.test \
  --bfla-url https://staging.example.test/admin/diagnostics \
  --low-priv-token "$LOW_PRIV_TOKEN" \
  --json bfla-report.json
```

The tool does not infer the intended role policy from a URL name. The operator must define why the endpoint is privileged and must validate the result against the application’s authorization model.

## Other assessment modes

The `--callback` option is reserved for an OAST or callback endpoint owned by the operator and is intended for controlled SSRF verification. The `--scan-vulns` option performs low-impact SQL-error and reflected-canary observations; it does not perform exploitation, extraction, destructive writes, or filter-bypass attempts. Endpoint discovery probes a small set of paths and records only live HTTP responses.

| Option | Function | Required input |
|---|---|---|
| `--target` | Base URL used for live API observations | Authorized HTTP(S) URL |
| `--idor-url` | One known resource endpoint for BOLA comparison | Authorized resource URL |
| `--token-a`, `--token-b` | Two approved test identities | Temporary test tokens |
| `--bfla-url` | One known privileged function endpoint | Authorized read-only endpoint |
| `--low-priv-token` | Low-privilege identity for BFLA | Temporary test token |
| `--callback` | Operator-owned SSRF callback | Owned callback URL |
| `--scan-vulns` | Enables low-impact SQLi/XSS indicators | Explicit opt-in |
| `--json` | Output report path | `api_report.json` |

## Local verification

The repository includes tests that start a real local HTTP server using Python’s standard-library `ThreadingHTTPServer`. These tests do not fabricate a scan report and do not call an external target. They verify that the implementation sends two different authorization headers, interprets `200`, `201`, `401`, and `403` correctly, compares the two response bodies, and does not place tokens in the finding output.

```bash
python3 -m py_compile main.py tests/test_api.py
python3 -m unittest discover -s tests -p "test_*.py"
```

The local server is a test fixture owned by the test process; it is not a replacement for an authorized staging scan. A staging scan is required to validate behavior against an actual application authorization policy.

## GitHub Actions CI/CD

The workflow at `.github/workflows/api_inspector_ci.yml` has two stages. The first stage runs on every push and pull request and executes the local HTTP unit tests. The second stage runs after the unit tests on a push to `main` or through `workflow_dispatch`. It validates that the staging hostname belongs to an explicit allowlist, then runs the authorized scan and uploads the JSON report as an artifact.

Configure the following values in the repository settings:

| Name | Location | Purpose |
|---|---|---|
| `STAGING_API_URL` | Actions secret | Base URL of the owned staging API |
| `IDOR_URL` | Actions secret | Known resource endpoint for the BOLA comparison |
| `BFLA_URL` | Actions secret | Known read-only privileged endpoint |
| `USER_TOKEN_A` | Actions secret | Approved identity A |
| `USER_TOKEN_B` | Actions secret | Approved identity B |
| `LOW_PRIV_TOKEN` | Actions secret | Approved low-privilege identity |
| `STAGING_ALLOWED_HOSTS` | Actions repository variable | Comma-separated exact hostnames allowed for scans |

The workflow passes tokens through `GHOST_TOKEN_A`, `GHOST_TOKEN_B`, and `GHOST_LOW_PRIV_TOKEN` environment variables. It does not echo their values or pass them as command-line arguments. If an IDOR or BFLA secret set is incomplete, the workflow performs discovery-only behavior rather than guessing credentials or targets.

A manual trigger is available from **Actions → GHOST-APIInspector Enterprise CI/CD → Run workflow**. Use this only after confirming that the staging URL and all test identities are valid and within the written assessment scope.

## Report interpretation

A report is evidence from a particular URL, identity, time, and request path. `bola_potential_vulnerability: true` means that the two authorized identities received successful, identical non-empty bodies; it does not by itself prove an access-control defect. `bfla_potential_vulnerability: true` means that the supplied low-privilege identity received a success status from the supplied privileged endpoint; the application owner must confirm that the endpoint should be restricted.

Reports should be retained with the engagement scope, test-account identifiers, timestamps, and server-side logs. Remove bearer tokens, cookies, and personal data before sharing a report with students or publishing it.

## Repository layout

```text
main.py                         CLI and live HTTP inspection engine
tests/test_api.py               Local HTTP tests for BOLA and BFLA behavior
tests/test_core.py              Core repository checks
.github/workflows/              GitHub Actions unit and authorized staging workflow
todo.md                         Current maintenance checklist
```

## Limitations

The current implementation is a focused assessment utility, not a full API inventory platform. It does not parse every OpenAPI construct, understand every authorization scheme, prove ownership of a resource, or replace manual review of server-side authorization logs. It should not be used to test third-party targets without explicit authorization.

## License and responsible use

Use is limited to systems and programs for which the operator has permission. The repository is intended for security education, authorized assessment, and defensive engineering. Do not use it to access another user’s data, evade controls, or perform destructive actions.
