# A05 — Security Misconfiguration

## Overview

Security Misconfiguration (OWASP 2021 A05, 2025 A02) is one of the most common and preventable vulnerability categories. It occurs when security settings are not defined, implemented, or maintained properly. This includes missing security hardening, unnecessary features enabled, default accounts or passwords unchanged, overly verbose error handling, and misconfigured security headers. In a Ruby on Rails application, misconfiguration can span the framework itself, authentication libraries, authorization enforcement, database settings, container runtime, and cloud storage services.

For APRS, security misconfiguration is particularly dangerous because the platform manages sensitive sighting data, handles financial transactions through Stripe, stores geospatial coordinates that could deanonymize reporters, and runs a PostGIS-enabled database with specialized extensions. A single misconfiguration -- such as leaving `force_ssl` disabled, running the container as root, or forgetting to enable Pundit's `verify_authorized` callback -- can expose the entire platform to attack.

The risk is amplified by configuration drift between development and production environments. Rails defaults are developer-friendly, not security-hardened. Devise ships with conservative but not paranoid settings. Pundit does not enforce authorization verification by default. Active Storage URLs can leak pre-signed tokens if misconfigured. Each of these represents a surface where a missing or incorrect configuration line silently degrades the security posture of the entire application.

## APRS-Specific Attack Surface

- **Rails configuration**: `force_ssl`, `consider_all_requests_local`, `config.hosts`, session cookie settings, CSRF protection, log level
- **Devise configuration**: `paranoid` mode, `stretches`, `lockable` settings, password length, `confirmable`, `timeoutable`
- **Pundit configuration**: `after_action :verify_authorized`, `after_action :verify_policy_scoped` for index actions
- **Content Security Policy**: CSP header configuration in Rails initializer; default Rails scaffold leaves it commented out
- **PostGIS configuration**: Extension privileges, public schema exposure, unnecessary extensions (tiger_geocoder)
- **Active Storage service configuration**: Service URL exposure, public vs private bucket policies, pre-signed URL expiration
- **Solid Queue configuration**: Job encryption, queue access control, admin dashboard exposure
- **Dockerfile/container configuration**: Running as root, shell access in production, missing HEALTHCHECK, base image vulnerabilities
- **Database configuration**: `database.yml` credentials, connection pooling, SSL mode, statement timeout
- **CORS settings**: Overly permissive `Access-Control-Allow-Origin`, missing credential restrictions
- **Development vs production drift**: Debug mode, web-console, verbose logging, relaxed CSP in development leaking to production

## Examples

### Basic Level

#### Example 1: Missing `force_ssl` in Production

**Source:** https://guides.rubyonrails.org/configuring.html#config-force-ssl
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/environments/production.rb
# force_ssl is commented out or set to false. All traffic is unencrypted,
# session cookies can be intercepted, and HSTS is not set.
Rails.application.configure do
  # config.force_ssl = true  # <-- commented out!
  config.assume_ssl = false
end
```

**Secure Fix:**
```ruby
# config/environments/production.rb
# force_ssl redirects HTTP to HTTPS, sets HSTS header, and marks cookies
# as Secure. assume_ssl tells Rails the app is behind an SSL-terminating
# proxy so it generates https:// URLs.
Rails.application.configure do
  config.assume_ssl = true
  config.force_ssl = true

  # Exclude the health check endpoint from SSL redirect so load balancers
  # can probe over HTTP on the internal network.
  config.ssl_options = {
    redirect: { exclude: ->(request) { request.path == "/up" } },
    hsts: { subdomains: true, preload: true, expires: 1.year.to_i }
  }
end
```

#### Example 2: Weak Devise Password Configuration

**Source:** https://github.com/heartcombo/devise/wiki/How-To:-Set-up-simple-password-complexity-requirements
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/initializers/devise.rb
# Default Devise settings are not hardened for a production application
# handling sensitive UAP sighting data and payment information.
Devise.setup do |config|
  config.password_length = 6..128         # too short minimum
  config.stretches = Rails.env.test? ? 1 : 11  # below OWASP recommendation
  # config.paranoid = false               # default: reveals whether email exists
  # config.lock_strategy = :none          # default: no account lockout
  # config.maximum_attempts = nil         # default: unlimited login attempts
end
```

**Secure Fix:**
```ruby
# config/initializers/devise.rb
# Hardened Devise configuration following OWASP Authentication guidelines.
# paranoid mode prevents user enumeration, lockable prevents brute force,
# bcrypt stretches set to 12+ for APRS security requirements.
Devise.setup do |config|
  # Paranoid mode: identical response for valid/invalid emails
  config.paranoid = true

  # Password complexity
  config.password_length = 12..128

  # bcrypt cost factor: 12 stretches (CLAUDE.md requires 12+)
  config.stretches = Rails.env.test? ? 1 : 12

  # Account lockout after 5 failed attempts
  config.lock_strategy = :failed_attempts
  config.maximum_attempts = 5
  config.unlock_strategy = :time
  config.unlock_in = 30.minutes

  # Session timeout for inactive users
  config.timeout_in = 30.minutes

  # Email confirmation required before sign-in
  config.reconfirmable = true

  # Remember-me cookie settings
  config.remember_for = 2.weeks
  config.expire_all_remember_me_on_sign_out = true

  # Sign out via DELETE only (CSRF protection)
  config.sign_out_via = :delete

  # Pepper for additional password security layer
  # config.pepper = Rails.application.credentials.dig(:devise, :pepper)
end
```

#### Example 3: Missing Pundit `verify_authorized` Enforcement

**Source:** https://github.com/varvet/pundit#ensuring-policies-and-scopes-are-used
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/application_controller.rb
# Pundit is included but verify_authorized is not enforced.
# Developers can forget to call `authorize` in any controller action
# and no error will be raised, silently bypassing authorization.
class ApplicationController < ActionController::Base
  include Pundit::Authorization
  # Missing: after_action :verify_authorized
  # Missing: after_action :verify_policy_scoped, only: :index

  allow_browser versions: :modern
end
```

**Secure Fix:**
```ruby
# app/controllers/application_controller.rb
# verify_authorized ensures every action calls `authorize`.
# verify_policy_scoped ensures every index action uses `policy_scope`.
# If a developer forgets, Pundit raises an error in development/test
# and logs a critical warning in production.
class ApplicationController < ActionController::Base
  include Pundit::Authorization

  after_action :verify_authorized
  after_action :verify_policy_scoped, only: :index

  allow_browser versions: :modern

  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized

  private

  # @param exception [Pundit::NotAuthorizedError] the authorization error
  # @return [void]
  def user_not_authorized(exception)
    Rails.logger.warn(
      "Pundit authorization denied",
      user_id: current_user&.id,
      policy: exception.policy.class.name,
      query: exception.query,
      record: exception.record.class.name
    )

    flash[:alert] = "You are not authorized to perform this action."
    redirect_back(fallback_location: root_path)
  end
end
```

### Intermediate Level

#### Example 4: Debug Mode and Verbose Errors in Production

**Source:** https://guides.rubyonrails.org/configuring.html#config-consider-all-requests-local
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/environments/production.rb
# consider_all_requests_local shows full stack traces to users in production.
# This exposes internal file paths, gem versions, database queries, and
# environment variables to attackers.
Rails.application.configure do
  config.consider_all_requests_local = true  # NEVER in production
  config.log_level = :debug                  # logs PII and sensitive data
  config.active_record.verbose_query_logs = true  # exposes SQL in logs
end
```

**Secure Fix:**
```ruby
# config/environments/production.rb
# Production must never expose internal details. Error pages should be
# static HTML that reveals nothing about the application stack.
Rails.application.configure do
  config.consider_all_requests_local = false
  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info")
  config.active_record.verbose_query_logs = false

  # Structured logging with request ID for correlation
  config.log_tags = [:request_id]
  config.logger = ActiveSupport::TaggedLogging.logger($stdout)

  # Disable deprecation output in production logs
  config.active_support.report_deprecations = false
end

# public/404.html, public/422.html, public/500.html
# Static error pages that reveal no application internals.
# These files should be plain HTML with no server-side rendering.
```

#### Example 5: Commented-Out Content Security Policy

**Source:** https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/initializers/content_security_policy.rb
# The entire CSP configuration is commented out (Rails default scaffold).
# Without CSP, the application is vulnerable to XSS, clickjacking,
# and data injection attacks.

# Rails.application.configure do
#   config.content_security_policy do |policy|
#     policy.default_src :self, :https
#     ...
#   end
# end
```

**Secure Fix:**
```ruby
# config/initializers/content_security_policy.rb
# Strict CSP configuration for APRS. Uses nonce-based script loading
# compatible with importmap-rails and Turbo. Restricts all resource
# loading to same-origin and explicitly allowed CDNs.
Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self
    policy.font_src    :self, :data
    policy.img_src     :self, :data, "https://*.digitaloceanspaces.com"
    policy.object_src  :none
    policy.script_src  :self
    policy.style_src   :self
    policy.connect_src :self
    policy.frame_ancestors :none
    policy.base_uri    :self
    policy.form_action :self

    # Report CSP violations to a monitoring endpoint
    policy.report_uri "/csp-violation-reports"
  end

  # Generate nonces for importmap and inline scripts/styles
  config.content_security_policy_nonce_generator = ->(request) {
    request.session.id.to_s
  }
  config.content_security_policy_nonce_directives = %w[script-src style-src]

  # Start in report-only mode during rollout, then switch to enforcing
  # config.content_security_policy_report_only = true
end
```

#### Example 6: Misconfigured Active Storage Service URL Exposure

**Source:** https://guides.rubyonrails.org/active_storage_overview.html#proxy-mode
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/storage.yml
# Public bucket with no access control. Pre-signed URLs have excessively
# long expiration. Service URL reveals the bucket name and region, which
# aids reconnaissance.
digitalocean:
  service: S3
  access_key_id: <%= ENV["DO_SPACES_ACCESS_KEY"] %>
  secret_access_key: <%= ENV["DO_SPACES_SECRET_KEY"] %>
  region: nyc3
  bucket: aprs-evidence-public  # public bucket!
  endpoint: https://nyc3.digitaloceanspaces.com
  public: true  # files are world-readable!

# config/environments/production.rb
Rails.application.configure do
  config.active_storage.service = :digitalocean
  # Missing: config.active_storage.resolve_model_to_route = :rails_storage_proxy
end
```

**Secure Fix:**
```ruby
# config/storage.yml
# Private bucket with server-side encryption. Short pre-signed URL
# expiration. Proxy mode hides the storage backend from clients.
digitalocean:
  service: S3
  access_key_id: <%= Rails.application.credentials.dig(:digitalocean, :spaces_access_key) %>
  secret_access_key: <%= Rails.application.credentials.dig(:digitalocean, :spaces_secret_key) %>
  region: nyc3
  bucket: aprs-evidence-private
  endpoint: https://nyc3.digitaloceanspaces.com
  public: false
  upload:
    server_side_encryption: "AES256"
    cache_control: "private, max-age=3600"

# config/environments/production.rb
# Proxy mode routes all file downloads through the Rails app,
# hiding the storage backend URL and enabling authorization checks.
Rails.application.configure do
  config.active_storage.service = :digitalocean
  config.active_storage.resolve_model_to_route = :rails_storage_proxy

  # Short expiration for any pre-signed URLs that might be generated
  config.active_storage.service_urls_expire_in = 5.minutes
end

# config/initializers/active_storage.rb
# Ensure Active Storage blobs cannot be accessed without authorization
# by using proxy mode and a custom controller.
Rails.application.config.after_initialize do
  ActiveStorage::Blob.class_eval do
    # @return [Boolean] always false to prevent direct public URLs
    def service_url_for_direct_upload(*)
      raise "Direct uploads must go through the authenticated upload endpoint"
    end
  end
end
```

#### Example 7: Overly Permissive CORS Configuration

**Source:** https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/initializers/cors.rb
# Wildcard origin allows any website to make authenticated requests
# to the APRS API, enabling CSRF-like attacks on the API and data
# exfiltration from authenticated sessions.
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins "*"                       # any origin!
    resource "*",                      # any path!
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options],
      credentials: true,              # sends cookies with wildcard origin
      max_age: 86_400
  end
end
```

**Secure Fix:**
```ruby
# config/initializers/cors.rb
# CORS is restricted to the known frontend origin(s) and API paths only.
# Credentials are allowed only for specific origins (not wildcard).
# Non-API paths do not need CORS headers at all.
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins ENV.fetch("CORS_ALLOWED_ORIGINS", "https://aprs.example.com").split(",")

    resource "/api/v1/*",
      headers: %w[Authorization X-API-Key Content-Type Accept],
      methods: [:get, :post, :put, :patch, :delete, :options],
      credentials: false, # API uses API key header, not cookies
      max_age: 600,       # 10 minutes, not 24 hours
      expose: %w[X-Request-Id X-RateLimit-Remaining X-RateLimit-Reset]
  end

  # No CORS for web routes — they are same-origin only
end
```

### Advanced Level

#### Example 8: Docker Container Running as Root

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```dockerfile
# Dockerfile
# Single-stage build with shell, compiler, and running as root.
# If the application is compromised, the attacker has root access
# inside the container and can install tools, modify files, and
# potentially escape the container.
FROM ruby:3.4.8
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install
COPY . .
RUN bundle exec rails assets:precompile
EXPOSE 3000
CMD ["bin/rails", "server", "-b", "0.0.0.0"]
# Runs as root by default
# Shell available (/bin/bash, /bin/sh)
# Compiler available (gcc, make)
# No health check
```

**Secure Fix:**
```dockerfile
# Dockerfile
# Multi-stage build using Chainguard Ruby base image (Wolfi).
# Runtime stage has no shell, no compiler, runs as nonroot (UID 65532).
# HEALTHCHECK instruction enables container orchestrator liveness probes.

# --- Builder stage ---
FROM cgr.dev/chainguard/ruby:latest-dev AS builder
WORKDIR /app

COPY Gemfile Gemfile.lock ./
RUN bundle config set --local deployment true && \
    bundle config set --local without 'development test' && \
    bundle install --jobs 4

COPY . .
RUN SECRET_KEY_BASE_DUMMY=1 bundle exec rails assets:precompile && \
    rm -rf tmp/cache vendor/bundle/ruby/*/cache

# --- Runtime stage ---
FROM cgr.dev/chainguard/ruby:latest
WORKDIR /app

# Copy only what's needed from builder
COPY --from=builder /app /app

# Run as nonroot user (UID 65532, built into Chainguard images)
USER nonroot

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["ruby", "-e", "require 'net/http'; Net::HTTP.get(URI('http://localhost:3000/up'))"]

CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
```

#### Example 9: Database Configuration with Exposed Credentials and Missing SSL

**Source:** https://guides.rubyonrails.org/configuring.html#configuring-a-database
**Status:** [VERIFIED]

**Vulnerable Code:**
```yaml
# config/database.yml
# Hardcoded credentials, no SSL, no connection timeout, no statement
# timeout. If this file is committed to git or exposed, credentials
# are compromised. Missing SSL means database traffic is unencrypted.
production:
  adapter: postgis
  encoding: unicode
  database: aprs_production
  username: aprs_admin
  password: SuperSecret123!
  host: db.internal.example.com
  port: 5432
  pool: 25
  # No SSL mode
  # No statement_timeout
  # No connect_timeout
```

**Secure Fix:**
```yaml
# config/database.yml
# Credentials from environment variables or Rails credentials.
# SSL required for production. Statement timeout prevents long-running
# queries from exhausting connections. Connect timeout prevents pool
# exhaustion when the database is unreachable.
production:
  adapter: postgis
  encoding: unicode
  database: <%= ENV.fetch("DATABASE_NAME", "aprs_production") %>
  username: <%= Rails.application.credentials.dig(:database, :username) %>
  password: <%= Rails.application.credentials.dig(:database, :password) %>
  host: <%= ENV.fetch("DATABASE_HOST") %>
  port: <%= ENV.fetch("DATABASE_PORT", 5432) %>
  pool: <%= ENV.fetch("RAILS_MAX_THREADS", 5) %>
  sslmode: verify-full
  sslca: <%= ENV.fetch("DATABASE_SSL_CA_PATH", "/etc/ssl/certs/ca-certificates.crt") %>
  connect_timeout: 5
  statement_timeout: 30_000  # 30 seconds max query time
  prepared_statements: true
  advisory_locks: true
  variables:
    statement_timeout: "30s"
    lock_timeout: "10s"
    idle_in_transaction_session_timeout: "60s"
```

#### Example 10: PostGIS Unnecessary Extensions and Public Schema Exposure

**Source:** https://postgis.net/docs/manual-3.4/postgis_installation.html
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# db/migrate/XXXXXX_enable_postgis.rb
# Enables PostGIS with all default extensions including tiger_geocoder,
# which is unnecessary for APRS and increases the attack surface.
# PostGIS functions are installed in the public schema, accessible to all.
class EnablePostgis < ActiveRecord::Migration[8.1]
  def change
    enable_extension "postgis"
    enable_extension "postgis_tiger_geocoder"  # unnecessary, large attack surface
    enable_extension "fuzzystrmatch"           # only needed for tiger_geocoder
    # All installed in public schema by default
  end
end
```

**Secure Fix:**
```ruby
# db/migrate/XXXXXX_enable_postgis.rb
# Only enable the PostGIS extension needed for APRS geography operations.
# Install in a dedicated schema to limit exposure. Drop unnecessary
# extensions that increase the attack surface.
class EnablePostgis < ActiveRecord::Migration[8.1]
  def up
    # Create a dedicated schema for PostGIS functions
    execute "CREATE SCHEMA IF NOT EXISTS postgis"
    execute "GRANT USAGE ON SCHEMA postgis TO aprs_app"

    # Enable only the core PostGIS extension
    enable_extension "postgis"

    # Drop unnecessary extensions if they exist (e.g., from default images)
    execute "DROP EXTENSION IF EXISTS postgis_tiger_geocoder CASCADE"
    execute "DROP EXTENSION IF EXISTS fuzzystrmatch CASCADE"
    execute "DROP EXTENSION IF EXISTS address_standardizer CASCADE"

    # Revoke public schema creation from default role
    execute "REVOKE CREATE ON SCHEMA public FROM PUBLIC"
  end

  def down
    disable_extension "postgis"
    execute "DROP SCHEMA IF EXISTS postgis CASCADE"
  end
end
```

#### Example 11: Solid Queue Admin Dashboard Exposed Without Authentication

**Source:** https://github.com/rails/solid_queue#web-ui
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# config/routes.rb
# Solid Queue's web dashboard (Mission Control) is mounted without
# authentication. Anyone can view, retry, and delete background jobs,
# including jobs that process Stripe webhooks and evidence uploads.
Rails.application.routes.draw do
  mount MissionControl::Jobs::Engine, at: "/jobs"
  # No authentication constraint!
end
```

**Secure Fix:**
```ruby
# config/routes.rb
# Mount Mission Control behind admin authentication constraint.
# Only admin users can access the job dashboard.
Rails.application.routes.draw do
  authenticate :user, ->(user) { user.admin? } do
    mount MissionControl::Jobs::Engine, at: "/admin/jobs"
  end

  # Alternative: HTTP basic auth for non-Devise setups
  # mount MissionControl::Jobs::Engine, at: "/admin/jobs",
  #   constraints: AdminConstraint.new
end

# app/constraints/admin_constraint.rb
# Route constraint that verifies admin role before allowing access
# to sensitive admin-only routes.
class AdminConstraint
  # @param request [ActionDispatch::Request] the incoming request
  # @return [Boolean] whether the request should be routed
  def matches?(request)
    user = request.env["warden"]&.user
    user&.admin? || false
  end
end
```

## Checklist

- [ ] `config.force_ssl = true` is set in `config/environments/production.rb`
- [ ] `config.assume_ssl = true` is set when behind an SSL-terminating proxy
- [ ] HSTS is configured with `subdomains: true` and `preload: true`
- [ ] `config.consider_all_requests_local = false` in production
- [ ] Log level is `info` or higher in production (never `debug`)
- [ ] `config.active_record.verbose_query_logs = false` in production
- [ ] Devise `paranoid` mode is enabled
- [ ] Devise `password_length` minimum is 12 characters
- [ ] Devise `stretches` is 12 or higher (except test environment)
- [ ] Devise `lock_strategy` is `:failed_attempts` with `maximum_attempts: 5`
- [ ] Devise `timeoutable` is enabled with appropriate timeout
- [ ] `after_action :verify_authorized` is in `ApplicationController`
- [ ] `after_action :verify_policy_scoped, only: :index` is in `ApplicationController`
- [ ] Content Security Policy is enabled and enforced (not commented out)
- [ ] CSP `frame-ancestors` is set to `:none` to prevent clickjacking
- [ ] CSP `object-src` is set to `:none`
- [ ] CSP nonce generator is configured for importmap-rails compatibility
- [ ] Active Storage service is configured with `public: false`
- [ ] Active Storage uses proxy mode (`resolve_model_to_route = :rails_storage_proxy`)
- [ ] Pre-signed URL expiration is 5 minutes or less
- [ ] Storage credentials are in Rails credentials, not environment variables or hardcoded
- [ ] CORS origins are restricted to known frontend domains (no wildcard)
- [ ] CORS does not allow credentials with wildcard origins
- [ ] CORS is only applied to API paths, not all routes
- [ ] Database credentials are in Rails credentials, not in `database.yml`
- [ ] Database connection uses `sslmode: verify-full` in production
- [ ] `statement_timeout` is configured to prevent long-running queries
- [ ] PostGIS tiger_geocoder extension is removed
- [ ] Unnecessary PostgreSQL extensions are not enabled
- [ ] Dockerfile uses multi-stage build with Chainguard base image
- [ ] Container runs as nonroot (UID 65532)
- [ ] Container has no shell access in runtime stage
- [ ] Dockerfile includes a `HEALTHCHECK` instruction
- [ ] Solid Queue admin dashboard requires admin authentication
- [ ] `config.hosts` is configured in production to prevent DNS rebinding
- [ ] `filter_parameters` includes all sensitive fields (password, token, key, secret, stripe)
- [ ] Development-only gems (web-console, debug) are not in production group
- [ ] `config.action_mailer.default_url_options` uses the real production host
