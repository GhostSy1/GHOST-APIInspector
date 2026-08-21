
# Current Work Items

- [x] Add local HTTP unit tests for BFLA and IDOR behavior.
- [x] Add encrypted environment variable support for CI tokens.
- [x] Add staging host allowlist validation in GitHub Actions.
- [x] Configure authorized BFLA and IDOR scan workflow with JSON artifact output.
- [ ] Add SARIF conversion for confirmed findings.
- [ ] Validate the workflow against a user-owned staging API.

## Portfolio hardening backlog

- [x] Keep the implementation evidence-based, local or explicitly authorized, and free of fabricated results or credentials.
- [x] Add repository-specific tests and CI validation
- [x] Expand README with architecture, installation, CLI, outputs, limits, and responsible-use guidance
- [x] Add a license and security reporting policy

## Professional Feature Expansion Backlog

- [x] Add domain-specific validation rules and robust error boundaries
- [x] Implement extensible report exporters (JSON, CSV, SARIF 2.1.0)
- [ ] Incorporate append-only evidence hashing and provenance tracking
- [x] Expand unit test coverage with realistic fixture inputs
- [ ] Add structured remediation guidance and severity-based triage scoring
- [ ] Launch without arguments and prompt for required target input
- [ ] Prompt for report paths with sensible defaults
- [ ] Keep --help concise and preserve non-interactive execution
- [ ] Keep README and CLI reference aligned with the actual prompts
- [ ] Add an interactive execution check
- [ ] Remove code comments from files changed in this pass
