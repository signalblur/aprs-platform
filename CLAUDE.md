# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
APRS (Anomalous Phenomena Reporting System) is an open-source MUFON fork for UAP sighting data collection, enrichment, and investigation. Licensed under AGPL v3. Built with Ruby on Rails 8.1, PostgreSQL + PostGIS.

## Environment Setup
- Ruby 3.4.8 via rbenv — **always prefix Ruby/Rails commands with:** `eval "$(rbenv init - zsh)"`
- PostgreSQL 16 + PostGIS 3.4 runs in an Apple Container (IP: `192.168.64.3`, user: `aprs_dev`)
- No Docker — use Apple Containers CLI at `/opt/homebrew/bin/container`
- libpq installed via Homebrew (needed for pg gem compilation)

## Common Commands

```bash
# Initialize rbenv (required before any Ruby/Rails command)
eval "$(rbenv init - zsh)"

# Database container management
bin/db-container start    # Start PostGIS container
bin/db-container stop     # Stop container
bin/db-container status   # Check container status

# Database setup
bundle exec rails db:create db:migrate

# Run all tests
bundle exec rspec

# Run a single test file
bundle exec rspec spec/models/user_spec.rb

# Run a specific test by line number
bundle exec rspec spec/models/user_spec.rb:42

# Linting
bundle exec rubocop --parallel

# Security scanning
bundle exec brakeman --no-pager

# Dependency audit
bundle exec bundler-audit check

# Regenerate OpenAPI docs (Rswag)
bundle exec rake rswag:specs:swaggerize

# Start dev server
bin/dev
```

## Git Safety — Repository Allowlist
- **ONLY repository allowed:** `git@github.com:signalblur/aprs-platform.git`
- Before ANY `git push`, `git remote`, `gh pr`, `gh issue`, or `gh api` command, verify the remote URL matches the allowlisted repo
- NEVER add, modify, or push to any other remote repository
- NEVER create PRs or issues on any other repository
- If the remote URL does not match, STOP and alert the user immediately

## Git Conventions
- Branch strategy: `main` (production), `feature/<name>` (per-feature)
- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `security:`, `infra:`, `refactor:`
- One logical change per commit
- Semantic version tags: v0.1.0, v0.2.0 per milestone
- Never commit: `.env`, `master.key`, credentials, secrets, large binaries
- Squash merge feature branches to main
- WIP commits on feature branches use prefix: `WIP: feat: <feature> - <state>`

## Development Workflow
- TRUE TDD: Write the test FIRST, then write the minimal code to make it pass, then refactor
- All tests must pass before committing
- SimpleCov 100% line coverage enforced (line + branch coverage, configured in `spec/rails_helper.rb`)

## Code Style
- YARD docs on all public methods (`@param`, `@return`, `@raise`)
- Methods <20 lines, classes <200 lines, max 3 nesting levels
- No N+1 queries (use `.includes()`)
- Reversible migrations
- Unified JSON structured logging via `Rails.logger`
- No PII in logs
- Specific exception classes, rescue specific exceptions
- Filter sensitive params from logs (currently configured: password, password_confirmation, token, api_key, key, secret, stripe, stripe_customer_id, stripe_subscription_id). **TODO:** add PII filters: name, first_name, last_name, contact_info, phone, latitude, longitude

## Security Non-Negotiables
- Pundit `authorize` in EVERY controller action (enforced by `after_action :verify_authorized, except: :index`)
- Pundit `policy_scope` in EVERY index action (enforced by `after_action :verify_policy_scoped, only: :index`)
- **Pundit uses `authorize` (no bang) — `authorize!` is CanCanCan, NOT Pundit**
- Strong Parameters on EVERY controller
- Parameterized queries ONLY (never string interpolation in SQL)
- File uploads: validate content-type AND magic bytes
- `force_ssl` in production
- CSP headers: initializer exists but is currently commented out — enable before production
- Rate limit auth + submission endpoints
- Devise: paranoid mode ON, password min 12 chars, lockable after 5 attempts, bcrypt stretches 12+
- Web controllers MUST have CSRF protection enabled
- API controllers (`Api::V1::BaseController < ActionController::API`) skip CSRF, authenticate via X-Api-Key header (SHA256 digest lookup). Always check `user.active_for_authentication?` after key lookup to enforce Devise lockable/confirmable controls.
- **Future (Stripe — not yet implemented):** Stripe webhook must verify `Stripe-Signature`, store event IDs (idempotency), re-fetch data from API, use pessimistic locks on Membership updates. Never trust webhook payloads for authorization decisions.
- No `skip_authorization` without documented justification

## PostGIS Conventions
- SRID 4326 for all geography columns
- Geography columns (not geometry) for accurate distance calculations
- GiST spatial indexes on all location columns
- Store `observed_at` as `timestamptz` (UTC in DB)
- Store observer's original timezone in `observed_timezone` column

## Architecture

### Controller/Authorization Pattern
`ApplicationController` enforces authentication (Devise) and authorization (Pundit) globally:
- `before_action :authenticate_user!` — all actions require login (Devise controllers excluded)
- `after_action :verify_authorized` — all non-index actions must call `authorize`
- `after_action :verify_policy_scoped` — all index actions must call `policy_scope`
- `rescue_from Pundit::NotAuthorizedError` — redirects with flash alert
- Controllers that skip auth (e.g., `HomeController`) must document justification in a comment

### User Model & Roles
- `User` uses Devise modules: `database_authenticatable`, `registerable`, `recoverable`, `rememberable`, `validatable`, `trackable`, `lockable`, `confirmable`
- Role enum: `member` (0, default), `investigator` (1), `admin` (2)
- Pundit policies check `user.role` for role gates
- **Future:** `Membership` model (Phase 1l) will add tier-based gating via `user.active_membership&.tier`

### Domain Model
Core entity graph (Phase 1a–1i):
- **User** → has_many :sightings (FK: `submitter_id`), has_many :evidences (FK: `submitted_by_id`) — both `dependent: :restrict_with_error`; has_many :api_keys (`dependent: :destroy`)
- **Shape** → has_many :sightings (`dependent: :restrict_with_error`) — 25 seeded UAP shape categories
- **Sighting** → belongs_to :submitter (User, optional for anonymous), belongs_to :shape
  - has_many :physiological_effects, :psychological_effects, :equipment_effects, :environmental_traces, :evidences, :witnesses (all `dependent: :destroy`)
  - PostGIS geography `location` (SRID 4326, GiST index), `observed_at` as timestamptz + `observed_timezone` (IANA)
  - Status enum: submitted → under_review → verified / rejected
- **PhysiologicalEffect / PsychologicalEffect** → belongs_to :sighting, severity enum (mild/moderate/severe)
- **EquipmentEffect** → belongs_to :sighting, equipment_type + effect_type (dual string fields)
- **EnvironmentalTrace** → belongs_to :sighting, PostGIS geography location, cross-field validation (measurement_unit required when measured_value present)
- **Evidence** → belongs_to :sighting + :submitted_by (User), has_one_attached :file (Active Storage), evidence_type enum (photo/video/audio/document/other), file validations (content-type allowlist, magic byte verification, 100 MB size limit)
- **Witness** → belongs_to :sighting, `encrypts :contact_info` (Active Record Encryption for PII), can be anonymous (nil name/contact_info)
- **ApiKey** → belongs_to :user, SHA256-digested `key_digest` (unique), `key_prefix` (8 chars), `name`, `active`, `expires_at`, `last_used_at`

### Sighting Display (Phase 1h)
- `SightingsController`: index (paginated list + filters + map) and show (detail + associations)
- Pagination: Pagy gem (20 per page, overflow: `:last_page`), `include Pagy::Backend` in ApplicationController
- Map: Leaflet 1.9.4 via Importmap, Stimulus `map_controller.js`, GeoJSON from `SightingsHelper#sightings_to_geojson`
- Filters: status, shape_id, date range, location radius (PostGIS), text search (ILIKE + `sanitize_sql_like`)
- Witness PII: `policy(witness).show_contact_info?` gates `contact_info` display (investigator/admin only)

### API Layer v1 (Phase 1i)
- **Separate trust boundary:** `Api::V1::BaseController < ActionController::API` (no CSRF, no sessions, no views)
- **Authentication:** X-Api-Key header → SHA256 digest lookup via `ApiKey.find_by_raw_key`; keys are never stored raw
- **Authorization:** Reuses existing Pundit policies (SightingPolicy, ShapePolicy, WitnessPolicy)
- **Rate limiting:** Rack::Attack — API by key prefix (300/min), unauthenticated (10/min/IP), login (5/20s/IP), password reset (5/hr/IP)
- **Endpoints:** `GET /api/v1/sightings` (paginated, filtered), `GET /api/v1/sightings/:id` (detail + associations), `GET /api/v1/shapes` (all shapes)
- **Serializers:** PORO serializers in `app/serializers/api/v1/` — no gems, compose via delegation
- **Filters:** `SightingsFilterable` concern shared between web and API controllers
- **PII gating:** Witness `contact_info` only included for investigator/admin (via `WitnessPolicy#show_contact_info?`)
- **JSON envelope:** `{data: [...], meta: {page, per_page, total, total_pages}}`

### Key Infrastructure
- Background jobs: Solid Queue (DB-backed, no Redis); also Solid Cache + Solid Cable
- Asset pipeline: Propshaft (Rails 8 default, not Sprockets)
- File storage: Active Storage (local in dev; DigitalOcean Spaces planned for production)
- Frontend: Importmap + Turbo + Stimulus + Tailwind CSS + Leaflet 1.9.4
- Pagination: Pagy ~> 9.0
- API docs: Rswag (rswag-api, rswag-ui, rswag-specs)
- Charts: Chartkick + Groupdate
- Dev email: `letter_opener_web` at `/letter_opener`
- Rate limiting: Rack::Attack (API, login, password reset throttles)

### Test Infrastructure
- RSpec + FactoryBot + Shoulda Matchers + WebMock + VCR
- Factories in `spec/factories/`
- Support configs in `spec/support/` (factory_bot, devise, shoulda_matchers, pundit, webmock, vcr)
- SimpleCov configured in `spec/rails_helper.rb` with 100% line minimum

### CI/CD
- GitHub Actions: `ci.yml` (RSpec + RuboCop + Brakeman + bundler-audit + importmap audit), `security-audit.yml`
- All CI steps use pinned action SHAs and `step-security/harden-runner`

## Dockerfile Hardening (for Agent 6)
- Base: `cgr.dev/chainguard/ruby:latest` (Wolfi, zero CVEs, daily rebuilds)
- NOTE: Free tier is `:latest` only — cannot pin Ruby version. This is the one accepted exception to our version pinning policy.
- Builder: `cgr.dev/chainguard/ruby:latest-dev` (has shell, apk, build tools)
- Runtime: `cgr.dev/chainguard/ruby:latest` (distroless, no shell, no package manager)
- Run as nonroot (UID 65532, default in Chainguard images)
- HEALTHCHECK via Ruby (no curl in distroless): `ruby -e "require 'net/http'; Net::HTTP.get(URI(...))"`
- Copy runtime libs (libpq, libvips, libjemalloc) from builder stage
- No Thruster — use `bundle exec puma -C config/puma.rb` directly
- Scan with trivy before deploy

## Agent Pipeline
This project uses an 8-agent development pipeline. See `.claude/agents/` for definitions.
Agent 8 (Documentarian) runs post-commit to keep README, CHANGELOG, and architecture docs in sync.
Pipeline state is tracked in `.claude/pipeline-state.md`.
Agent feedback is persisted in `.claude/reviews/`.
