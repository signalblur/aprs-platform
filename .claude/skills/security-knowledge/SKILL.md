# Skill: security-knowledge

## Trigger

Invoked internally by other agents and skills. Not typically called directly by the user.

Can also be invoked manually with `/security-knowledge` to display a summary of the loaded knowledge base.

## Description

Shared security reference skill that reads the OWASP security knowledge base and provides context-relevant security guidance to other agents. Acts as the security memory layer for the APRS agent pipeline.

## Consumers

| Agent                    | Usage                                                              |
|--------------------------|--------------------------------------------------------------------|
| Agent 2 (Builder)        | Query during code generation to avoid known anti-patterns          |
| Agent 5 (Code Reviewer)  | Load full checklists for security review pass                      |
| build-feature skill      | Reference during pipeline orchestration for security context       |

## Execution Steps

### 1. Load Knowledge Base

- Read all 12 files from `.claude/security-knowledge-base/`:
  - `01-broken-access-control.md`
  - `02-cryptographic-failures.md`
  - `03-injection.md`
  - `04-insecure-design.md`
  - `05-security-misconfiguration.md`
  - `06-vulnerable-outdated-components.md`
  - `07-software-supply-chain-failures.md`
  - `08-authentication-failures.md`
  - `09-software-data-integrity-failures.md`
  - `10-security-logging-alerting-failures.md`
  - `11-ssrf.md`
  - `12-mishandling-exceptional-conditions.md`
- If any file is missing or empty, warn: "Security knowledge base incomplete. Run `/security-baseline` first."

### 2. Context-Aware Filtering

When called by another agent with a context (e.g., "building a controller", "handling file uploads", "Stripe webhook"):

- Match the context against relevant OWASP categories:

| Context Keywords                        | Relevant OWASP Files                                        |
|-----------------------------------------|-------------------------------------------------------------|
| controller, action, route               | 01 (Access Control), 03 (Injection), 05 (Misconfiguration)  |
| authentication, login, session, devise  | 08 (Authentication Failures), 01 (Access Control)            |
| authorization, pundit, policy           | 01 (Access Control), 04 (Insecure Design)                    |
| file upload, active storage, attachment | 03 (Injection), 01 (Access Control), 11 (SSRF)              |
| stripe, webhook, payment, subscription  | 09 (Data Integrity), 02 (Cryptographic Failures)             |
| api, api key, token                     | 08 (Authentication), 01 (Access Control), 02 (Crypto)        |
| database, query, sql, postgis           | 03 (Injection), 05 (Misconfiguration)                        |
| logging, audit, log                     | 10 (Logging Failures), 02 (Cryptographic Failures)           |
| gem, dependency, bundle                 | 06 (Outdated Components), 07 (Supply Chain)                  |
| background job, solid queue, worker     | 04 (Insecure Design), 12 (Exceptional Conditions)            |
| error, exception, rescue                | 12 (Exceptional Conditions), 10 (Logging Failures)           |
| docker, container, deploy               | 05 (Misconfiguration), 07 (Supply Chain)                     |
| redirect, url, request                  | 11 (SSRF), 01 (Access Control)                               |

- Return only the relevant sections (Overview, APRS-Specific Attack Surface, matching examples, Checklist) from the matched files.
- If no context keywords match, return all checklists as a general reference.

### 3. Provide Checklist Output

When used by Agent 5 (Code Reviewer), compile a unified checklist from all 12 knowledge base files:

```markdown
# Security Review Checklist

## A01 — Broken Access Control
- [ ] Pundit `authorize` called in every controller action
- [ ] `verify_authorized` after_action present
- [ ] `policy_scope` used in index actions
- [ ] No `skip_authorization` without documented justification
...

## A02 — Cryptographic Failures
- [ ] Passwords hashed with bcrypt (stretches >= 12)
- [ ] API keys stored as SHA256 digest, never plaintext
- [ ] force_ssl enabled in production
- [ ] Sensitive data not logged
...

(continues for all 12 categories)
```

### 4. Provide Anti-Pattern Warnings

When used by Agent 2 (Builder), return anti-pattern summaries:

```markdown
# Security Anti-Patterns to Avoid

## DO NOT:
- Use string interpolation in SQL queries
- Skip Pundit authorization in any controller action
- Store API keys or passwords in plaintext
- Trust webhook payloads without signature verification
- Log PII (emails, names, locations, IP addresses)
- Use `send()` or `public_send()` with user-controlled input
- Serve Active Storage attachments without authorization checks
- Use `permit!` on Strong Parameters
- Rescue StandardError or Exception without re-raising
- Hard-code secrets or credentials anywhere in source

## ALWAYS:
- Use parameterized queries or ActiveRecord query interface
- Validate file content-type AND magic bytes on upload
- Verify Stripe webhook signatures before processing
- Re-fetch Stripe objects from API instead of trusting payload
- Use pessimistic locking on Membership updates from webhooks
- Rate limit authentication and submission endpoints
- Use `after_action :verify_authorized` in all controllers
- Use Strong Parameters with explicit permit lists
- Store observed_at as timestamptz with separate timezone column
- Use geography columns (not geometry) with SRID 4326
```

## Error Handling

- If the security knowledge base directory does not exist, return an error: "Security knowledge base not found. Run `/security-baseline` to create it."
- If individual files are missing, list the missing files and proceed with available ones.
- Never block the pipeline due to missing knowledge base files; instead, warn and continue with CLAUDE.md security rules as the baseline.

## Fallback Behavior

If the knowledge base is unavailable, fall back to the security rules defined in `CLAUDE.md` under "Security Non-Negotiables". These rules are always enforced regardless of knowledge base availability:

- Pundit `authorize!` in every controller action
- `verify_authorized` and `verify_policy_scoped` after_actions
- Strong Parameters on every controller
- Parameterized queries only
- File upload validation (content-type AND magic bytes)
- `force_ssl` in production
- CSP headers enabled
- Rate limiting on auth and submission endpoints
- Devise paranoid mode, 12+ char passwords, lockable, bcrypt 12+ stretches
- Stripe webhook signature verification, event ID idempotency, re-fetch from API, pessimistic locks
- API controllers skip CSRF, use API key auth
- Web controllers require CSRF protection
- No `skip_authorization` without documented justification
