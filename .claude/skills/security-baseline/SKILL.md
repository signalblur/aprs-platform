# Skill: security-baseline

## Trigger

`/security-baseline`

## Description

One-time OWASP knowledge base builder. Invokes Agent 1 (Security Auditor) to create a comprehensive security reference tailored to the APRS stack. This knowledge base is consumed by other agents (Builder and Code Reviewer) during the build-feature pipeline.

## Execution Steps

### 1. Check for Existing Knowledge Base

- Check if `.claude/security-knowledge-base/` already contains populated files.
- If files exist and are populated:
  - Prompt: "Security knowledge base already exists. Overwrite? (y/n)"
  - On "n": abort.
  - On "y": proceed and overwrite all files.

### 2. Invoke Agent 1 — Security Auditor

- The Security Auditor builds the knowledge base by researching each of the 12 unified OWASP risks.
- For each risk category, the agent must:
  - Research the risk using official OWASP documentation, published CVEs, and vendor advisories.
  - Generate 5-10 code examples at three difficulty levels: **basic**, **intermediate**, and **advanced**.
  - Every example must include both the **vulnerable code** and the **secure fix**.
  - All examples must use the APRS technology stack: Ruby on Rails 8.1, Devise, Pundit, Stripe API, PostGIS, Active Storage, Solid Queue.
  - Every example must cite at least one authoritative source: official documentation URL, CVE identifier, or published security advisory.
  - If a citation cannot be verified, the example must be marked with `[UNVERIFIED]` at the top.

### 3. Create Knowledge Base Files

Create the following 12 files in `.claude/security-knowledge-base/`:

| File                                        | OWASP Risk                                |
|---------------------------------------------|-------------------------------------------|
| `01-broken-access-control.md`               | A01 — Broken Access Control               |
| `02-cryptographic-failures.md`              | A02 — Cryptographic Failures              |
| `03-injection.md`                           | A03 — Injection                           |
| `04-insecure-design.md`                     | A04 — Insecure Design                     |
| `05-security-misconfiguration.md`           | A05 — Security Misconfiguration           |
| `06-vulnerable-outdated-components.md`      | A06 — Vulnerable and Outdated Components  |
| `07-software-supply-chain-failures.md`      | A07 — Software Supply Chain Failures      |
| `08-authentication-failures.md`             | A08 — Authentication Failures             |
| `09-software-data-integrity-failures.md`    | A09 — Software and Data Integrity Failures|
| `10-security-logging-alerting-failures.md`  | A10 — Security Logging and Alerting Failures|
| `11-ssrf.md`                                | A11 — Server-Side Request Forgery (SSRF)  |
| `12-mishandling-exceptional-conditions.md`  | A12 — Mishandling Exceptional Conditions  |

### 4. File Format

Each knowledge base file must follow this structure:

```markdown
# <OWASP Risk ID> — <Risk Name>

## Overview
<2-3 paragraph description of the risk, why it matters, and how it applies to APRS>

## APRS-Specific Attack Surface
<Bullet list of where this risk appears in the APRS architecture>

## Examples

### Basic Level

#### Example 1: <Title>
**Source:** <URL, CVE, or advisory citation>
**Status:** [VERIFIED] or [UNVERIFIED]

**Vulnerable Code:**
```ruby
# Description of the vulnerability
<code>
```

**Secure Fix:**
```ruby
# Description of the fix and why it works
<code>
```

### Intermediate Level

#### Example N: <Title>
...

### Advanced Level

#### Example N: <Title>
...

## Checklist
- [ ] <Actionable item agents can verify during code review>
- [ ] <Another actionable item>
```

### 5. Verification Pass

After all 12 files are created:

- Count total examples per file; flag any file with fewer than 5.
- Count `[UNVERIFIED]` examples; if more than 20% of total examples are unverified, warn the user.
- Validate that every file contains all three levels (basic, intermediate, advanced).
- Validate that every example has both vulnerable and secure code blocks.
- Log summary: total examples, verified count, unverified count, per-file breakdown.

### 6. Completion

- Log: "Security knowledge base created with <N> total examples across 12 OWASP risk categories."
- Record creation timestamp in `.claude/security-knowledge-base/README.md` with metadata:
  - Date created
  - Rails version targeted
  - OWASP reference version (2021 Top 10 + API Top 10 unified)
  - Total example count
  - Unverified example count

## APRS Stack Context for Examples

All examples must be written using these specific technologies:

| Component           | Technology                           |
|---------------------|--------------------------------------|
| Framework           | Ruby on Rails 8.1                    |
| Authentication      | Devise (paranoid mode, lockable)     |
| Authorization       | Pundit (verify_authorized enforced)  |
| Payments            | Stripe API (webhooks, subscriptions) |
| Geospatial          | PostGIS (SRID 4326, geography cols)  |
| File Storage        | Active Storage + DigitalOcean Spaces |
| Background Jobs     | Solid Queue (DB-backed)              |
| Database            | PostgreSQL 16+ with PostGIS          |
| API Authentication  | SHA256 API key digest, monthly quotas|
| Container Runtime   | Chainguard Ruby base image (Wolfi)   |

## Source Priority for Citations

1. **Official documentation** (Rails guides, Devise wiki, Pundit README, Stripe docs, PostGIS docs)
2. **CVE database** (cve.org, NVD)
3. **OWASP official pages** (owasp.org)
4. **Published security advisories** (GitHub advisories, RubySec)
5. **Peer-reviewed research** (conference papers, journal articles)
6. **Reputable security blogs** (only if no other source available, marked `[UNVERIFIED]`)
