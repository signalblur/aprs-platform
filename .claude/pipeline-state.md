# Pipeline State

No feature currently in progress.

## Completed Phases
- [x] Phase 0: Agent pipeline setup (8 agents, 5 skills, CLAUDE.md, pipeline-state.md)
- [x] Phase 0: GitHub Actions CI/CD (3 workflows: ci.yml, security-audit.yml, deploy.yml)
- [x] Phase 0: Round table review — ALL fixable items resolved (32/32 fixes). See `.claude/reviews/round-table-review.md`
- [x] Phase 1a: Bootstrap
  - Ruby 3.4.8 via rbenv
  - Rails 8.1.2 with Tailwind CSS dark theme
  - PostgreSQL 16 + PostGIS 3.4 via Apple Containers (container IP: 192.168.64.3)
  - Gemfile: 44 dependencies, 164 gems installed
  - database.yml: postgis adapter, container host
  - RSpec + FactoryBot + SimpleCov (100% target) + Shoulda + WebMock + VCR
  - spec/support/ config files (factory_bot, devise, shoulda, pundit, webmock, vcr)
  - Pundit installed (ApplicationPolicy generated)
  - .rubocop.yml with rubocop-rails + rubocop-rspec
  - .dockerignore updated
  - Procfile (web + worker)
  - bin/db-container management script
  - config/application.rb: generators, filter_parameters, UTC timezone
  - force_ssl enabled in production
  - Sensitive params filtered
  - Database created + PostGIS verified
  - RSpec runs clean (0 examples, 0 failures)
- [x] Phase 1b: Security Knowledge Base (OWASP KB)
  - 12 OWASP risk files created in `.claude/security-knowledge-base/`
  - ~120 examples across 3 difficulty levels (basic, intermediate, advanced)
  - ~79% verified, ~21% unverified (marked with [UNVERIFIED])
  - 11,240 total lines
  - README.md with metadata
  - All examples use APRS stack (Rails 8.1, Devise, Pundit, Stripe, PostGIS, Active Storage, Solid Queue)

## Git State
- SSH key (ed25519) in macOS keychain — working with GitHub
- CLAUDE.md has repo allowlist: ONLY `git@github.com:signalblur/aprs-platform.git`
- Current branch: main
- Uncommitted changes: Phase 1b KB files, CLAUDE.md git safety section, round table fixes

## Next Phase: 1c (User Auth & Registration)
- Install Devise, generate User model with role enum (member/investigator/admin)
- Devise hardening: paranoid, lockable, confirmable, 12+ char passwords, stretches 12
- Build using `/build-feature` pipeline (Agent 2 -> 3 -> 4 -> 5)
- Depends on: Phase 1b (complete)

## Upcoming Phases
- Phase 1d: Shape reference data (model + 25+ category seed)
- Phase 1e: Sighting submission core (Sections 1-4, PostGIS location)
- Phase 1f: Sighting effects (4 effect models, Sections 5-8)
- Phase 1g: Evidence + Witness (Sections 9-10, Active Storage)
- Phase 1h: Sighting display (Leaflet map, list, show, search/filter)
- Phase 1i: API Layer v1 (REST JSON, API keys, rate limiting)
- Phase 1j: API documentation (Rswag OpenAPI specs)
- Phase 1k: Investigation management (case assign, status, audit)
- Phase 1l: Stripe integration (payment, membership tiers, webhooks)
- Phase 1m: Admin dashboard (Tailwind + Chartkick)

## Remaining Pre-Decisions
- C8: Open-Meteo commercial licensing — decide before Phase 2a
