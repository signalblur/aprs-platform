# Round Table Review — Consolidated Report

**Date:** 2026-02-09
**Agents:** All 7 (Security Auditor, Builder, Dependency Verifier, Test Reviewer, Code Reviewer, Deployer, API Integration Expert)
**Scope:** Full agent pipeline, skill definitions, CI/CD workflows, architecture plan, existing bootstrap code

---

## Executive Summary

All 7 expert agents completed independent reviews of the full APRS platform architecture and bootstrapped codebase. The combined output identified ~146 findings (many duplicated across agents). After de-duplication, the unique actionable findings are organized below by severity.

**Key themes:**
1. **Cross-document contradictions** -- Devise config, Pundit `authorize` vs `authorize!`, `verify_authorized` scope, `submitter_id` nullability — **ALL FIXED**
2. **Dockerfile diverges from spec** -- Uses Debian slim instead of Chainguard Wolfi, has shell access, no HEALTHCHECK, references missing Thruster binary — **FIXED**
3. **GitHub Actions security gaps** -- Actions were pinned to tags not SHAs, no harden-runner, no explicit permissions — **FIXED**
4. **API integration concerns** -- Open-Meteo commercial licensing, ADSB.lol historical data is file dumps not API, OpenSky OAuth2 migration — **FIXED (except C8 licensing decision)**
5. **Missing conventions** -- Service objects, pagination, API response format, error handling, caching strategy — **SERVICE OBJECTS + EXCEPTION HANDLING + TIME HELPERS FIXED; rest deferred to relevant phases**

---

## CRITICAL Findings (Must Fix Before Phase 1b)

### C1. `authorize!` is NOT a Pundit method -- it is CanCanCan [Dep Verifier]
- **STATUS: FIXED** — Changed to `authorize` in CLAUDE.md and builder.md

### C2. Devise `unlock_strategy` contradiction [Security, Builder, Dep Verifier, Code Reviewer]
- **STATUS: FIXED** — Standardized to `:both` in rails-conventions/SKILL.md

### C3. `verify_authorized` scope contradiction [Builder, Code Reviewer]
- **STATUS: FIXED** — Standardized to `except: :index` in CLAUDE.md, builder.md, code-reviewer.md

### C4. CSP headers entirely commented out [Security Auditor]
- **STATUS: DEFERRED TO PHASE 1c** (requires Devise installation first)

### C5. `submitter_id` nullability conflict [Builder, Security Auditor]
- **STATUS: FIXED** — Made nullable for anonymous submissions, `optional: true` on association

### C6. `confidence_score` validation uses invalid `in:` option [Builder]
- **STATUS: FIXED** — Changed to `greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0`

### C7. Dockerfile uses wrong base image + references missing Thruster [Deployer, Security Auditor]
- **STATUS: FIXED** — Rewritten with Chainguard Wolfi (`cgr.dev/chainguard/ruby:latest`), multi-stage, distroless runtime, nonroot UID 65532, Ruby-based HEALTHCHECK, no Thruster

### C8. Open-Meteo commercial use licensing [API Expert]
- **STATUS: DECIDED** — No commercial-licensed products allowed. Weather enrichment (Open-Meteo, Visual Crossing) scrapped from Phase 2a/2b until a fully open-source alternative is available.

### C9. ADSB.lol historical data is file dumps, not queryable API [API Expert]
- **STATUS: FIXED** — API Expert updated with live API endpoints vs historical file dump distinction

### C10. OpenSky Network now requires OAuth2 [API Expert]
- **STATUS: FIXED** — API Expert updated with OAuth2 migration note and endpoint clarifications

---

## HIGH Findings

### H1. No CORS configuration [Security Auditor]
- **STATUS: DEFERRED TO Phase 1i (API Layer)**

### H2. No session timeout/management controls [Security Auditor]
- **STATUS: DEFERRED TO Phase 1c**

### H3. Dependency Verifier "relaxed constraints" undefined [Security Auditor, Builder]
- **STATUS: FIXED** — Removed self-verification; escalates to human after 3 failures

### H4. rswag allowlist entry does not match actual gem names [Dep Verifier]
- **STATUS: FIXED** — Replaced with rswag-api, rswag-ui, rswag-specs

### H5. Missing gems in allowlist / stale gems in allowlist [Dep Verifier]
- **STATUS: FIXED** — Added importmap-rails, rubocop-rails-omakase, web-console, tzinfo-data; removed kamal, thruster, jbuilder

### H6. Agent 3 verification uses `instance_methods` only -- misses class methods/scopes [Builder, Dep Verifier]
- **STATUS: FIXED** — Added `bundle exec rails runner` as primary verification method

### H7. `active_membership` method referenced but not defined on User [Builder]
- **STATUS: FIXED** — Added method definition with YARD docs to domain model

### H8. Stripe webhook idempotency TOCTOU race condition [Builder]
- **STATUS: FIXED** — Added `rescue ActiveRecord::RecordNotUnique` to conventions

### H9. No DatabaseCleaner for system specs [Test Reviewer]
- **STATUS: DEFERRED TO Phase 1c** (needed before system specs are written)

### H10. filter_parameters missing PII fields [Security Auditor, Code Reviewer]
- **STATUS: FIXED** — Added api_key, name, first_name, last_name, contact_info, phone, latitude, longitude

### H11. Witness PII encryption is "should" not "must" [Security Auditor]
- **STATUS: FIXED** — Changed to MUST with `encrypts :contact_info` directive

### H12. No service object pattern guidance [Code Reviewer]
- **STATUS: FIXED** — Added full service object convention with example to rails-conventions

### H13. No global exception handler guidance [Code Reviewer]
- **STATUS: FIXED** — Added rescue_from patterns for Pundit, RecordNotFound, ParameterMissing

### H14. Launch Library 2 rate limit (15 req/hour) needs dedicated handling [API Expert]
- **STATUS: DEFERRED TO Phase 2e**

### H15. Deconfliction aggregation job missing [API Expert]
- **STATUS: FIXED** — Added `maybe_finalize!` method, atomic JSONB writes, and orchestration docs to domain model

### H16. SondeHub API endpoint missing from documentation [API Expert]
- **STATUS: FIXED** — Added REST API base URL, endpoints, and Swagger spec link

### H17. `sgp4` Ruby gem does not exist on RubyGems [Dep Verifier]
- **STATUS: FIXED** — Corrected to `ruby-sgp4sdp4`, documented alternatives (pure Ruby, Python Skyfield)

---

## MEDIUM Findings (Address During Relevant Phase)

| # | Finding | Agent(s) | Fix Phase | Status |
|---|---------|----------|-----------|--------|
| M1 | No HTTP security headers beyond CSP (X-Content-Type-Options, etc.) | Security | 1c | Deferred |
| M2 | No JSONB schema validation for enrichment API responses | Security | 2a | Deferred |
| M3 | No mass assignment protection verification for enum fields | Security | 1c | Deferred |
| M4 | `timestamptz` migration syntax not documented | Builder | 1e | Deferred |
| M5 | `observed_timezone` validation uses incomplete MAPPING (150 vs 590+ zones) | Builder, Dep Verifier | 1e | Deferred |
| M6 | Audit log trigger behavior undefined (when to fire, what to log) | Builder | 1c | Deferred |
| M7 | Effect model design discrepancy (has_one vs has_many, arrays vs columns) | Builder, Dep Verifier | 1f | Deferred |
| M8 | StripeWebhookEvent missing payload/source_ip columns vs plan | Builder | 1l | Deferred |
| M9 | No pagination conventions | Code Reviewer | 1h | Deferred |
| M10 | No API response format convention (envelope, error format) | Code Reviewer | 1i | Deferred |
| M11 | No database transaction handling guidance | Code Reviewer | 1e | Deferred |
| M12 | No N+1 query prevention beyond "use includes" | Code Reviewer | 1h | Deferred |
| M13 | Severity terminology inconsistency (SUGGESTION vs INFO) | Code Reviewer | — | **FIXED** |
| M14 | Agent 3 re-run after doc-only fixes is wasteful | Code Reviewer | — | **FIXED** |
| M15 | No branch coverage enforcement in SimpleCov | Test Reviewer | 1c | Deferred |
| M16 | No time manipulation convention (travel_to vs Timecop) | Test Reviewer | — | **FIXED** |
| M17 | No VCR cassette management guidelines for 13 APIs | Test Reviewer | 2a | Deferred |
| M18 | Sighting status transition matrix not enumerated | Test Reviewer | 1e | Deferred |
| M19 | Evidence XOR validation needs 4 explicit test cases | Test Reviewer | 1g | Deferred |
| M20 | Devise extra settings (sign_in_after_reset, reconfirmable) not in Builder/Code Reviewer | Code Reviewer | 1c | Deferred |
| M21 | ~~Weather data mapping gaps (moon_phase, twilight, precipitation type)~~ | API Expert | 2a | Scrapped (C8) |
| M22 | ~~Unit conversion not documented (Celsius to F, km/h to mph)~~ | API Expert | 2a | Scrapped (C8) |
| M23 | Per-API rate limiter pattern not defined | API Expert | 2a | Deferred |
| M24 | Retryable vs non-retryable HTTP error distinction not documented | API Expert | 2a | Deferred |

---

## LOW Findings (Nice-to-Have)

| # | Finding | Agent(s) | Status |
|---|---------|----------|--------|
| L1 | GitHub Actions were pinned to tags not SHAs | Security, Deployer | **FIXED** |
| L2 | No deploy concurrency control | Deployer | **FIXED** |
| L3 | Security audit artifacts not uploaded | Deployer | **FIXED** |
| L4 | API key timing oracle (constant-time comparison) | Security | Phase 1i |
| L5 | Stripe webhook IP allowlisting | Security | Phase 1l |
| L6 | AuditLog missing updated_at (correct for append-only) | Builder | Phase 1c |
| L7 | altitude_feet as decimal vs integer | Builder | Phase 1e |
| L8 | Visible Planets API fragility -- JPL Horizons as primary | API Expert | Phase 2g |
| L9 | Where The ISS At redundancy -- CelesTrak+SGP4 as primary | API Expert | Phase 2d |
| L10 | CelesTrak error rate blocking (100 errors/2hr window) | API Expert | Phase 2c |
| L11 | DeconflictionResult `military_check` field is orphaned | API Expert | Phase 2a |
| L12 | No `.env.example` for developer onboarding | Deployer | Phase 3 |
| L13 | FactoryBot lint not enabled in CI | Test Reviewer | Phase 1c |
| L14 | No error tracking service (Sentry/Honeybadger) | Deployer | Phase 3 |

---

## All Fixes Applied

### Session 1 (GitHub Actions Hardening)
1. **GitHub Actions SHA pinning** -- All 3 workflows updated with full commit SHA pins
2. **StepSecurity Harden-Runner** -- Added as first step in every job across all 3 workflows
3. **Explicit permissions** -- All 3 workflows now declare minimal `permissions:`
4. **persist-credentials: false** -- All checkout steps hardened
5. **Deploy concurrency control** -- Added `concurrency: group: production-deploy`
6. **Security audit artifact upload** -- Reports now uploaded as CI artifacts (30-day retention)
7. **Deployer agent** -- Added comprehensive "GitHub Actions Security Hardening" section covering 12 attack vectors

### Session 2 (10 Immediate Action Items)
8. `authorize!` → `authorize` in CLAUDE.md and builder.md
9. `unlock_strategy` standardized to `:both` across all files
10. `verify_authorized, except: :index` standardized across all files
11. `confidence_score` validation fixed in domain model
12. Relaxed constraints removed from dependency verifier
13. Gem allowlist corrected (rswag split, missing/stale gems)
14. `active_membership` method added to domain model
15. PII fields added to filter_parameters across all files
16. Witness encryption changed from "should" to "MUST"
17. `submitter_id` made nullable for anonymous submissions

### Session 3 (Remaining Fixes)
18. **Dockerfile rewritten** -- Chainguard Wolfi, multi-stage, distroless runtime, nonroot, HEALTHCHECK, no Thruster
19. **ADSB.lol** -- Live API endpoints documented separately from historical file dumps
20. **OpenSky** -- OAuth2 migration documented, endpoint clarifications
21. **SondeHub** -- REST API endpoint (`api.v2.sondehub.org`), Swagger spec linked
22. **SGP4** -- Gem name corrected to `ruby-sgp4sdp4`, alternatives documented
23. **Dep Verifier** -- Added `rails runner` as primary verification, dependency squatting detection
24. **Stripe webhook** -- TOCTOU race condition fixed with `rescue RecordNotUnique`
25. **Service object pattern** -- Full convention added to rails-conventions
26. **Global exception handler** -- `rescue_from` patterns added to rails-conventions
27. **Time manipulation** -- `travel_to` convention added, Timecop prohibited
28. **Severity terminology** -- Standardized to CRITICAL/WARNING/SUGGESTION (not INFO)
29. **Build-feature pipeline** -- Relaxed constraints removed from re-entry rules
30. **Deployer agent** -- Updated base image docs for Wolfi free tier
31. **CLAUDE.md** -- Updated Dockerfile section with Wolfi details
32. **Documentarian agent** -- New Agent 8 for README/CHANGELOG/docs maintenance

---

## Remaining Deferred Items (Tracked for Future Phases)

- **Phase 1c:** CSP headers, session management, Devise settings alignment, DatabaseCleaner, branch coverage, HTTP security headers, mass assignment protection, audit log triggers
- **Phase 1e:** timestamptz docs, timezone validation, status transition matrix, transaction handling, altitude type
- **Phase 1f:** Effect model design (has_one vs has_many)
- **Phase 1g:** Evidence XOR validation test cases
- **Phase 1h:** Pagination conventions, N+1 prevention
- **Phase 1i:** CORS, API response format, API key timing oracle
- **Phase 1l:** Stripe webhook patterns, StripeWebhookEvent columns, subscription tests, webhook IP allowlisting
- **Phase 2a:** API rate limiters, VCR management, JSONB validation, retryable errors, military_check field (weather data mapping + unit conversions scrapped per C8 decision)
- **Phase 2c:** SGP4 verification, CelesTrak error handling
- **Phase 2d:** ISS API redundancy evaluation
- **Phase 2g:** Visible Planets reliability evaluation
- **Phase 3:** DO app spec, .env.example, error tracking, FactoryBot lint

### Decisions Resolved
- **C8:** Open-Meteo commercial licensing — **DECIDED:** No commercial-licensed products. Weather enrichment scrapped until open-source alternative found.
