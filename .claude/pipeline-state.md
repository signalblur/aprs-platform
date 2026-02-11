# Pipeline State

No feature currently in progress. Phase 1l complete, ready for Phase 1m.

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

- [x] Phase 1g: Evidence + Witness
  - Evidence model: belongs_to :sighting + :submitted_by (User), has_one_attached :file (Active Storage)
  - Evidence enum: photo (0), video (1), audio (2), document (3), other (4)
  - File validations: content-type allowlist (jpeg, png, webp, mp4, mpeg, wav, pdf), magic byte verification, 100 MB size limit
  - Witness model: belongs_to :sighting, encrypts :contact_info (Active Record Encryption)
  - EvidencePolicy: read/create=all, update=submitter+admin, destroy=admin
  - WitnessPolicy: read/create=all, update=sighting submitter+admin, destroy=admin, show_contact_info?=investigator+admin
  - Active Storage installed (blobs, attachments, variant_records tables)
  - Active Record Encryption configured (credentials + test env deterministic keys)
  - User has_many :evidences (FK: submitted_by_id, dependent: restrict_with_error)
  - Sighting has_many :evidences + :witnesses (dependent: destroy)
  - Shapes factory fix: sequence-based names to avoid Faker uniqueness exhaustion
  - 2 factories, 2 model specs, 2 policy specs = 90 new examples (360 total)
  - 100% line coverage, RuboCop clean, Brakeman clean
  - M19 (XOR sighting/investigation constraint): Deferred to Phase 1k (Investigation model required)

- [x] Phase 1h: Sighting Display (List, Show, Map, Search/Filter)
  - Pagy pagination gem (v9.4, 20 per page, overflow: :last_page)
  - Leaflet 1.9.4 via Importmap (ESM from jspm.io) + Stimulus map controller
  - SightingsController: index + show with Pundit, Pagy, filters
  - Index filters: status, shape, date range, location radius, text search (ILIKE)
  - GeoJSON helper: sightings_to_geojson with HTML-escaped popups
  - search_description scope (ILIKE + sanitize_sql_like for SQL injection safety)
  - Views: dark APRS theme (Tailwind), nav bar, filter form, map, sighting cards
  - Show: detail view with all effects, evidence, witnesses (PII gated)
  - Layout: sticky nav, flash messages, footer
  - Deleted hello_controller.js scaffold
  - 39 new specs (399 total), 100% line+branch coverage, RuboCop clean, Brakeman clean

- [x] Phase 1i: API Layer v1 (Read-Only, API Key Auth, Rate Limiting)
  - ApiKey model: SHA256-digested keys, key_prefix for identification, active/expires_at lifecycle
  - ApiKeyPolicy: index/create=all, show/destroy=owner+admin, scope by user/admin
  - SightingsFilterable concern: extracted from SightingsController for web+API reuse
  - PORO serializers: ShapeSerializer, SightingSerializer, SightingDetailSerializer (no gems)
  - Api::V1::BaseController: inherits ActionController::API (separate trust boundary, no CSRF/sessions)
  - API key auth via X-Api-Key header → SHA256 digest lookup → touch_last_used!
  - Api::V1::SightingsController: index (paginated, filtered) + show (detail with all 6 associations)
  - Api::V1::ShapesController: index (all shapes ordered by name)
  - Witness PII gating: contact_info only for investigator/admin (WitnessPolicy#show_contact_info?)
  - Rack::Attack rate limiting: API by key (300/min), unauthenticated (10/min), login (5/20s), password reset (5/hr)
  - Custom 429 JSON responder
  - JSON envelope: {data: [...], meta: {page, per_page, total, total_pages}}
  - 158 new specs (557 total), 100% line+branch coverage, RuboCop clean, Brakeman clean

- [x] Phase 1j: API Documentation (Rswag / OpenAPI 3.0.3)
  - Rswag initializers (rswag_api.rb, rswag_ui.rb) + Swagger UI at /api-docs
  - spec/swagger_helper.rb: OpenAPI 3.0.3 spec with 14 component schemas (allOf composition)
  - Security scheme: X-Api-Key (apiKey type, header)
  - Shapes integration spec (2 examples: 200, 401)
  - Sightings integration spec (6 examples: index 200/401, show 200 member/200 investigator/401/404)
  - Witness PII gating documented in schema + tested with dual response examples
  - swagger/v1/swagger.yaml generated and committed
  - RuboCop exclusions for Rswag DSL patterns (DescribeClass, EmptyExampleGroup, VariableName, etc.)
  - 8 new specs (565 total), 100% line+branch coverage, RuboCop clean, Brakeman clean

- [x] Phase 1k: Investigation Management
  - Investigation model: case_number (auto-generated APRS-YYYYMMDD-XXXX), title, description, status/priority/classification enums, findings, assigned_investigator FK, opened_at/closed_at timestamptz
  - InvestigationNote model: nested notes with note_type enum (general/status_change/assignment/finding)
  - Evidence M19 XOR constraint resolved: DB CHECK + model validation — evidence belongs to sighting XOR investigation
  - Sighting → optional belongs_to :investigation
  - InvestigationPolicy: member scoped to linked sightings, investigator/admin full access, findings gated
  - InvestigationNotePolicy: investigator assigned only, admin full, member denied
  - Web CRUD: InvestigationsController (full CRUD + link/unlink sighting), InvestigationNotesController (create/destroy)
  - Views: index (paginated + filters), show (detail + notes timeline + findings gated), form, nav link
  - API v1: read-only investigations endpoint with policy-gated findings/notes serialization
  - Rswag: InvestigationSummary, InvestigationDetail, InvestigationNote schemas + integration specs
  - 214 new specs (779 total), 100% line+branch coverage, RuboCop clean, Brakeman clean

- [x] Phase 1l: Membership Tiers (Admin-Assigned) + Stripe Cleanup
  - Stripe gem + all Stripe references permanently removed from codebase
  - Membership model: tier enum (free/professional/organization), granted_by FK, notes, starts_at/expires_at, active
  - Partial unique index: one active membership per user at DB level
  - TierLimits concern: LIMITS hash, tier/tier_limit/within_tier_limit? methods on User
  - Tier gating: SightingPolicy#create?, EvidencePolicy#create?, ApiKeyPolicy#create? enforce limits
  - MembershipPolicy: admin CRUD, non-admin own-only show, no destroy (deactivate instead)
  - MembershipsController: admin-gated index/new/create/edit/update, user show for own
  - Api::V1::MembershipsController: GET /api/v1/membership (singular) — tier + limits for current user
  - Api::V1::MembershipSerializer: tier, active, starts_at, expires_at, limits hash
  - Rswag: Membership + TierLimits schemas, integration spec (3 examples)
  - Views: index/show/form/new/edit with Tailwind, admin-gated nav link
  - Security KB updated: Stripe examples retained as reference patterns
  - 119 new specs (898 total), 100% line+branch coverage, RuboCop clean, Brakeman clean

## Next Phase: 1m

## Upcoming Phases
- Phase 1m: Admin dashboard (Tailwind + Chartkick)

## Resolved Pre-Decisions
- C8: Open-Meteo commercial licensing — **DECIDED: No commercial-licensed products.** Weather enrichment (Open-Meteo, Visual Crossing) scrapped from Phase 2a/2b until a fully open-source alternative is available.
