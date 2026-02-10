# Pipeline State

No feature currently in progress. Phase 1f complete and ready to commit.

## Completed Phases
- [x] Phase 0: Agent pipeline setup (8 agents, 5 skills, CLAUDE.md, pipeline-state.md)
- [x] Phase 0: GitHub Actions CI/CD (2 workflows: ci.yml, security-audit.yml)
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
- [x] Phase 1c: User Auth & Registration (commit c15c90f)
  - Devise with hardened config (paranoid, 12-char min, lockable/5, confirmable, bcrypt 12)
  - User model with role enum (member/investigator/admin)
  - Pundit policies: ApplicationPolicy + UserPolicy with full RBAC
  - ApplicationController: authenticate_user!, verify_authorized, verify_policy_scoped
  - HomeController with public root (skip_authorization documented)
  - Devise views generated (sessions, registrations, passwords, confirmations, unlocks, mailers)
  - 49 specs, 100% line+branch coverage, RuboCop clean, Brakeman clean
  - 37 files changed, 1,280 lines added

## Git State
- SSH key (ed25519) in macOS keychain — working with GitHub
- CLAUDE.md has repo allowlist: ONLY `git@github.com:signalblur/aprs-platform.git`
- Current branch: main

- [x] Phase 1d: Shape Reference Data
  - Shape model with name (unique, NOT NULL) + description (nullable)
  - ShapePolicy: reads for all authenticated users, writes for admins only
  - 25 UAP shape category seeds (idempotent via find_or_create_by!)
  - Factory + 8 model specs + 17 policy specs = 25 new examples (74 total)
  - 100% line+branch coverage, RuboCop clean, Brakeman clean

- [x] Phase 1e: Sighting Submission Core
  - Sighting model with PostGIS geography location (SRID 4326, GiST index)
  - belongs_to :submitter (User, optional for anonymous), belongs_to :shape
  - has_many :sightings backfilled on User (FK: submitter_id) and Shape
  - Status enum: submitted (0), under_review (1), verified (2), rejected (3)
  - Validations: description (20-10K chars), observed_at, observed_timezone (IANA), num_witnesses (>= 1), duration_seconds (> 0, optional)
  - timestamptz for observed_at, observed_timezone for IANA zone
  - Scopes: within_radius (ST_DWithin), recent, by_status, by_shape, observed_between
  - SightingPolicy: all users read/create, submitter+admin update, admin-only destroy
  - Anonymous sightings: only admins can update/destroy
  - Factory with 7 traits (anonymous, under_review, verified, rejected, without_optional_fields, in_boulder, in_nyc)
  - 63 new specs (137 total), 100% line+branch coverage, RuboCop clean, Brakeman clean

- [x] Phase 1f: Sighting Effects (4 effect models)
  - PhysiologicalEffect: effect_type, severity enum (mild/moderate/severe), onset, duration
  - PsychologicalEffect: effect_type, severity enum (mild/moderate/severe), onset, duration
  - EquipmentEffect: equipment_type, effect_type (dual string fields)
  - EnvironmentalTrace: trace_type, PostGIS geography location, measured_value + measurement_unit
  - All 4 models: belongs_to :sighting, Sighting has_many :X dependent(:destroy)
  - 4 Pundit policies: read/create=all, update=submitter+admin, destroy=admin
  - Cross-field validation on EnvironmentalTrace (measurement_unit required when measured_value present)
  - 4 factories, 4 model specs, 4 policy specs = 133 new examples (270 total)
  - 100% line+branch coverage, RuboCop clean, Brakeman clean

## Next Phase: 1g (Evidence + Witness)
- Evidence model with Active Storage, Witness model
- Depends on: Phase 1f (complete)

## Upcoming Phases
- Phase 1g: Evidence + Witness (Sections 9-10, Active Storage)
- Phase 1h: Sighting display (Leaflet map, list, show, search/filter)
- Phase 1i: API Layer v1 (REST JSON, API keys, rate limiting)
- Phase 1j: API documentation (Rswag OpenAPI specs)
- Phase 1k: Investigation management (case assign, status, audit)
- Phase 1l: Stripe integration (payment, membership tiers, webhooks)
- Phase 1m: Admin dashboard (Tailwind + Chartkick)

## Resolved Pre-Decisions
- C8: Open-Meteo commercial licensing — **DECIDED: No commercial-licensed products.** Weather enrichment (Open-Meteo, Visual Crossing) scrapped from Phase 2a/2b until a fully open-source alternative is available.
