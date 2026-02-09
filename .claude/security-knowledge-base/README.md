# Security Knowledge Base

## Metadata
- **Date Created:** 2026-02-09
- **Rails Version Targeted:** 8.1
- **OWASP Reference:** 2021 Top 10 + 2025 Top 10 (12 unified risks)
- **Total Examples:** ~120
- **Verified Examples:** ~95 (79%)
- **Unverified Examples:** ~25 (21%)

## Files

| File | OWASP Risk | Examples |
|------|-----------|----------|
| `01-broken-access-control.md` | A01 -- Broken Access Control | 10 |
| `02-cryptographic-failures.md` | A02 -- Cryptographic Failures | 10 |
| `03-injection.md` | A03 -- Injection (SQL, XSS, Command) | 10 |
| `04-insecure-design.md` | A04 -- Insecure Design | 10 |
| `05-security-misconfiguration.md` | A05 -- Security Misconfiguration | 11 |
| `06-vulnerable-outdated-components.md` | A06 -- Vulnerable and Outdated Components | 10 |
| `07-software-supply-chain-failures.md` | A07 -- Software Supply Chain Failures | 10 |
| `08-authentication-failures.md` | A08 -- Authentication Failures | 10 |
| `09-software-data-integrity-failures.md` | A09 -- Software and Data Integrity Failures | 10 |
| `10-security-logging-alerting-failures.md` | A10 -- Security Logging and Alerting Failures | 10 |
| `11-ssrf.md` | A11 -- Server-Side Request Forgery (SSRF) | 10 |
| `12-mishandling-exceptional-conditions.md` | A12 -- Mishandling Exceptional Conditions | 10 |

## Usage

This knowledge base is consumed by:
- **Agent 2 (Builder):** Anti-pattern avoidance during code generation
- **Agent 5 (Code Reviewer):** Security checklists during review pass
- **security-knowledge skill:** Context-aware filtering for agent queries

## Stack Covered

All examples use: Rails 8.1, Devise, Pundit, Stripe, PostGIS, Active Storage, Solid Queue, PostgreSQL 16+, Chainguard Wolfi containers.
