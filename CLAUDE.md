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
- **Future (Stripe/API — not yet implemented):** Stripe webhook must verify `Stripe-Signature`, store event IDs (idempotency), re-fetch data from API, use pessimistic locks on Membership updates. API controllers (`Api::V1::BaseController`) skip CSRF, authenticate via API key header. Never trust webhook payloads for authorization decisions.
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
Core entity graph (Phase 1a–1f):
- **User** → has_many :sightings (FK: `submitter_id`, `dependent: :restrict_with_error`)
- **Shape** → has_many :sightings (`dependent: :restrict_with_error`) — 25 seeded UAP shape categories
- **Sighting** → belongs_to :submitter (User, optional for anonymous), belongs_to :shape
  - has_many :physiological_effects, :psychological_effects, :equipment_effects, :environmental_traces (all `dependent: :destroy`)
  - PostGIS geography `location` (SRID 4326, GiST index), `observed_at` as timestamptz + `observed_timezone` (IANA)
  - Status enum: submitted → under_review → verified / rejected
- **PhysiologicalEffect / PsychologicalEffect** → belongs_to :sighting, severity enum (mild/moderate/severe)
- **EquipmentEffect** → belongs_to :sighting, equipment_type + effect_type (dual string fields)
- **EnvironmentalTrace** → belongs_to :sighting, PostGIS geography location, cross-field validation (measurement_unit required when measured_value present)

### Key Infrastructure
- Background jobs: Solid Queue (DB-backed, no Redis); also Solid Cache + Solid Cable
- Asset pipeline: Propshaft (Rails 8 default, not Sprockets)
- File storage: Active Storage (local in dev; DigitalOcean Spaces planned for production)
- Frontend: Importmap + Turbo + Stimulus + Tailwind CSS
- API docs: Rswag (rswag-api, rswag-ui, rswag-specs)
- Charts: Chartkick + Groupdate
- Dev email: `letter_opener_web` at `/letter_opener`
- **Future:** `Api::V1::` namespace (Phase 1i)

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
