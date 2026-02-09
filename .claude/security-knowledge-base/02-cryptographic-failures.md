# A02 — Cryptographic Failures

## Overview

Cryptographic Failures (previously known as "Sensitive Data Exposure") ranked A02 in the OWASP 2021 Top 10 and A04 in the 2025 Top 10. This category covers failures related to cryptography — or the lack thereof — that lead to exposure of sensitive data. Common root causes include transmitting data in cleartext, using weak or obsolete cryptographic algorithms, using default or weak keys, not enforcing encryption, and improperly storing secrets.

For APRS, cryptographic failures are a high-severity concern because the platform stores multiple categories of sensitive data: witness contact information (PII), user credentials (passwords hashed via Devise/bcrypt), API keys for programmatic access, Stripe payment data relayed through webhooks, and geospatial coordinates that can identify exact observation locations. The platform also handles financial operations through Stripe webhooks, where failure to verify cryptographic signatures could allow an attacker to forge subscription events and grant themselves premium access.

The Rails 8.1 framework provides strong cryptographic defaults when properly configured — Active Record encryption for column-level encryption, Devise's bcrypt password hashing, and built-in credential management. However, each of these must be deliberately configured with appropriate parameters. A bcrypt cost factor that is too low, an API key stored in plaintext, or missing `force_ssl` can each independently compromise user data.

## APRS-Specific Attack Surface

- **Devise password hashing (bcrypt stretches)** — Devise defaults to 12 bcrypt stretches in production, but if misconfigured to a lower value (e.g., 1 or 10 in all environments), passwords become vulnerable to brute-force attacks with modern GPU hardware.
- **API key storage** — API keys must be stored as SHA256 digests, never as plaintext. Plaintext storage means a database breach exposes every API consumer's key.
- **Stripe webhook signature verification** — Stripe signs every webhook with an HMAC (SHA256). Skipping `Stripe::Webhook.construct_event` verification allows forged events to manipulate Membership records.
- **`force_ssl` in production** — Without `force_ssl`, authentication tokens, session cookies, and API keys can be intercepted via man-in-the-middle attacks on HTTP connections.
- **Witness `contact_info` encryption** — Witness contact information (phone, email, address) is PII that must be encrypted at the application layer using Active Record Encryption (`encrypts :contact_info`). Database-level encryption alone is insufficient because it does not protect against application-layer data leaks.
- **Sensitive data in logs** — Rails logger can inadvertently capture passwords, API keys, Stripe tokens, and PII in log output. Parameter filtering must be comprehensive.
- **`master.key` and credentials management** — The `master.key` file decrypts `credentials.yml.enc`. If committed to version control or exposed in container images, all encrypted credentials (database passwords, Stripe keys, encryption keys) are compromised.
- **Session cookie encryption** — Rails encrypts session cookies by default, but weak `secret_key_base` or exposure of this value compromises all sessions.
- **TLS certificate validation** — Outbound HTTP calls to Stripe API, weather enrichment services, and deconfliction APIs must validate TLS certificates. Disabling verification (e.g., `OpenSSL::SSL::VERIFY_NONE`) exposes traffic to interception.

## Examples

### Basic Level

#### Example 1: Weak bcrypt Stretches for Password Hashing

**Source:** https://github.com/heartcombo/devise/blob/main/lib/devise.rb#L68
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/initializers/devise.rb
# VULNERABLE: stretches=1 in all environments. Even in production, passwords
# can be brute-forced in seconds on a modern GPU. Devise defaults to 12 in
# production but 1 in test — this overrides all environments.
Devise.setup do |config|
  config.stretches = 1
  config.paranoid = false
  config.password_length = 6..128
end
```

**Secure Fix:**
```ruby
# config/initializers/devise.rb
# SECURE: 12+ stretches in production/development, 1 in test (for speed).
# Paranoid mode prevents user enumeration. Minimum 12-char passwords.
Devise.setup do |config|
  config.stretches = Rails.env.test? ? 1 : 12
  config.paranoid = true
  config.password_length = 12..128
  config.lock_strategy = :failed_attempts
  config.maximum_attempts = 5
  config.unlock_strategy = :time
  config.unlock_in = 30.minutes
  config.reconfirmable = true
  config.expire_all_remember_me_on_sign_out = true
  config.sign_out_all_scopes = true
end
```

#### Example 2: Plaintext API Key Storage

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#api-keys
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/api_key.rb
# VULNERABLE: API key stored in plaintext. A database breach (SQL injection,
# backup theft, replica access) exposes all API keys in usable form.
class ApiKey < ApplicationRecord
  belongs_to :user

  before_create :generate_key

  private

  def generate_key
    self.key = SecureRandom.hex(32)
    # key is stored as-is in the database — plaintext
  end
end

# app/controllers/api/v1/base_controller.rb
class Api::V1::BaseController < ActionController::API
  private

  def authenticate_api_key!
    @current_api_key = ApiKey.find_by(key: request.headers["X-API-Key"])
    head :unauthorized unless @current_api_key
  end
end
```

**Secure Fix:**
```ruby
# app/models/api_key.rb
# SECURE: Only the SHA256 digest is stored. The plaintext key is returned
# once on creation and never stored. Authentication compares digests.
class ApiKey < ApplicationRecord
  belongs_to :user

  # key_digest is the only column stored in the database
  # key_prefix stores first 8 chars for identification in UI
  attribute :raw_key, :string

  before_create :generate_key_digest

  # @return [Boolean] whether the API key is currently active
  scope :active, -> { where(revoked_at: nil).where("expires_at > ?", Time.current) }

  private

  # @return [void]
  def generate_key_digest
    raw = SecureRandom.hex(32)
    self.raw_key = raw
    self.key_digest = Digest::SHA256.hexdigest(raw)
    self.key_prefix = raw[0..7]
  end
end

# app/controllers/api/v1/base_controller.rb
class Api::V1::BaseController < ActionController::API
  include Pundit::Authorization

  private

  # @return [void]
  def authenticate_api_key!
    key_value = request.headers["X-API-Key"]
    return head(:unauthorized) if key_value.blank?

    digest = Digest::SHA256.hexdigest(key_value)
    @current_api_key = ApiKey.active.find_by(key_digest: digest)
    return head(:unauthorized) unless @current_api_key

    @current_api_key.touch(:last_used_at)
  end
end
```

#### Example 3: Sensitive Data Logged in Plaintext

**Source:** https://guides.rubyonrails.org/configuring.html#config-filter-parameters
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/initializers/filter_parameter_logging.rb
# VULNERABLE: Only filters password. API keys, Stripe tokens, PII (witness
# contact info, names, coordinates) all appear in plaintext in log files.
Rails.application.config.filter_parameters += [:password]

# app/controllers/api/v1/sightings_controller.rb
# VULNERABLE: Logs full params including witness contact info
class Api::V1::SightingsController < Api::V1::BaseController
  def create
    Rails.logger.info("Sighting submission: #{params.inspect}")
    # Logs: {"witness"=>{"contact_info"=>"555-0123", "name"=>"John Doe"}, ...}
    @sighting = Sighting.new(sighting_params)
    authorize @sighting
    @sighting.save!
    render json: @sighting, status: :created
  end
end
```

**Secure Fix:**
```ruby
# config/initializers/filter_parameter_logging.rb
# SECURE: Comprehensive parameter filtering. All sensitive fields are replaced
# with [FILTERED] in logs. Includes PII, credentials, payment tokens, and
# geospatial data that could identify witnesses.
Rails.application.config.filter_parameters += [
  :password,
  :password_confirmation,
  :token,
  :key,
  :api_key,
  :secret,
  :stripe,
  :name,
  :first_name,
  :last_name,
  :contact_info,
  :phone,
  :email,
  :latitude,
  :longitude
]

# app/controllers/api/v1/sightings_controller.rb
# SECURE: Structured logging without PII. Log only non-sensitive metadata.
class Api::V1::SightingsController < Api::V1::BaseController
  # @return [void]
  def create
    @sighting = Sighting.new(sighting_params)
    authorize @sighting
    @sighting.save!
    Rails.logger.info(
      event: "sighting_created",
      sighting_id: @sighting.id,
      submitter_id: current_api_key.user_id,
      shape: @sighting.shape,
      observed_at: @sighting.observed_at
    )
    render json: @sighting, status: :created
  end
end
```

### Intermediate Level

#### Example 4: Missing Stripe Webhook Signature Verification

**Source:** https://docs.stripe.com/webhooks/signatures
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/stripe_webhooks_controller.rb
# VULNERABLE: Parses webhook body without verifying the Stripe-Signature header.
# An attacker can send forged events to grant themselves premium memberships
# or cancel other users' subscriptions.
class StripeWebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
    event = JSON.parse(request.body.read, symbolize_names: true)

    case event[:type]
    when "customer.subscription.updated"
      sub_data = event.dig(:data, :object)
      membership = Membership.find_by(stripe_subscription_id: sub_data[:id])
      membership&.update!(tier: map_tier(sub_data.dig(:plan, :id)))
    when "customer.subscription.deleted"
      sub_data = event.dig(:data, :object)
      membership = Membership.find_by(stripe_subscription_id: sub_data[:id])
      membership&.update!(status: "canceled", tier: "basic")
    end

    head :ok
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/stripe_webhooks_controller.rb
# SECURE: Verifies Stripe-Signature using the webhook endpoint secret.
# Rejects forged or tampered events. Delegates processing to background job.
class StripeWebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token
  # Justified: No user session context; authentication via Stripe-Signature
  skip_after_action :verify_authorized

  # @return [void]
  def create
    payload = request.body.read
    sig_header = request.headers["Stripe-Signature"]
    webhook_secret = Rails.application.credentials.dig(:stripe, :webhook_secret)

    begin
      event = Stripe::Webhook.construct_event(payload, sig_header, webhook_secret)
    rescue JSON::ParserError => e
      Rails.logger.warn(event: "stripe_webhook_parse_error", error: e.message)
      head :bad_request
      return
    rescue Stripe::SignatureVerificationError => e
      Rails.logger.warn(event: "stripe_webhook_signature_invalid", error: e.message)
      head :bad_request
      return
    end

    # Idempotency guard
    return head(:ok) if StripeWebhookEvent.exists?(stripe_event_id: event.id)

    StripeWebhookEvent.create!(stripe_event_id: event.id, event_type: event.type)
    ProcessStripeWebhookJob.perform_later(event.id, event.type)
    head :ok
  end
end
```

#### Example 5: Missing `force_ssl` in Production

**Source:** https://guides.rubyonrails.org/configuring.html#config-force-ssl
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/environments/production.rb
# VULNERABLE: force_ssl is disabled. Session cookies, API keys in headers,
# and all request/response bodies (including sighting data and witness PII)
# are transmitted in cleartext over HTTP.
Rails.application.configure do
  config.force_ssl = false
  # Or simply omitted — defaults to false
end
```

**Secure Fix:**
```ruby
# config/environments/production.rb
# SECURE: force_ssl redirects HTTP to HTTPS, sets HSTS header (max-age 2 years),
# and marks cookies as Secure. All traffic is encrypted in transit.
Rails.application.configure do
  config.force_ssl = true
  config.ssl_options = {
    hsts: {
      expires: 2.years.to_i,
      subdomains: true,
      preload: true
    },
    redirect: {
      exclude: ->(request) { request.path.start_with?("/health") }
    }
  }

  # Ensure cookies are secure and httponly
  config.session_store :cookie_store,
    key: "_aprs_session",
    secure: true,
    httponly: true,
    same_site: :lax
end
```

#### Example 6: Witness Contact Information Stored Without Encryption

**Source:** https://guides.rubyonrails.org/active_record_encryption.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/witness.rb
# VULNERABLE: contact_info is stored as plaintext in the database. A database
# breach (SQL injection, backup theft, compromised replica) exposes all
# witness phone numbers, emails, and addresses.
class Witness < ApplicationRecord
  belongs_to :sighting

  validates :contact_info, presence: true
end

# db/migrate/xxx_create_witnesses.rb
class CreateWitnesses < ActiveRecord::Migration[8.1]
  def change
    create_table :witnesses do |t|
      t.references :sighting, null: false, foreign_key: true
      t.string :contact_info  # Plaintext PII
      t.text :statement
      t.timestamps
    end
  end
end
```

**Secure Fix:**
```ruby
# app/models/witness.rb
# SECURE: contact_info is encrypted at the application layer using Active Record
# Encryption. Even if the database is breached, contact_info is ciphertext.
# deterministic: false prevents querying by encrypted value (more secure).
class Witness < ApplicationRecord
  belongs_to :sighting

  encrypts :contact_info, deterministic: false, downcase: false

  validates :contact_info, presence: true
end

# config/application.rb — Active Record Encryption must be configured
# with keys derived from credentials (never hardcoded)
module Aprs
  class Application < Rails::Application
    # Encryption keys are stored in credentials.yml.enc
    # Run: bin/rails db:encryption:init to generate keys
    # Then store in credentials:
    #   active_record_encryption:
    #     primary_key: <generated>
    #     deterministic_key: <generated>
    #     key_derivation_salt: <generated>
  end
end

# config/credentials.yml.enc (decrypted view — NEVER commit master.key)
# active_record_encryption:
#   primary_key: "a1b2c3d4..."
#   deterministic_key: "e5f6g7h8..."
#   key_derivation_salt: "i9j0k1l2..."

# db/migrate/xxx_create_witnesses.rb
class CreateWitnesses < ActiveRecord::Migration[8.1]
  def change
    create_table :witnesses do |t|
      t.references :sighting, null: false, foreign_key: true
      t.text :contact_info  # Stores ciphertext — Active Record Encryption
      t.text :statement
      t.timestamps
    end
  end
end
```

### Advanced Level

#### Example 7: `master.key` Committed to Version Control

**Source:** https://guides.rubyonrails.org/security.html#custom-credentials
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# .gitignore
# VULNERABLE: master.key is NOT in .gitignore. Once pushed, it is in the
# git history permanently — even if later removed from the working tree.
# An attacker with read access to the repo can decrypt all credentials:
# database password, Stripe secret key, encryption keys, webhook secrets.

# The file config/master.key contains:
# abc123def456...

# Anyone with this key can run:
# RAILS_MASTER_KEY=abc123def456 bin/rails credentials:show
# And see all secrets in plaintext.
```

**Secure Fix:**
```ruby
# .gitignore
# SECURE: master.key is git-ignored. In production, RAILS_MASTER_KEY is set
# as an environment variable (via container orchestration secrets, not .env).
/config/master.key
/config/credentials/*.key

# If master.key was EVER committed, it must be rotated:
# 1. Generate new master.key: bin/rails credentials:edit (creates new key)
# 2. Rotate ALL secrets stored in credentials (DB password, Stripe keys, etc.)
# 3. Use git filter-repo or BFG to remove the old key from git history
# 4. Force-push (with team coordination) and have all clones re-fetched

# config/credentials.yml.enc structure (for reference — this file IS committed)
# stripe:
#   secret_key: sk_live_...
#   publishable_key: pk_live_...
#   webhook_secret: whsec_...
# active_record_encryption:
#   primary_key: ...
#   deterministic_key: ...
#   key_derivation_salt: ...

# In production (e.g., container orchestration), set:
# ENV["RAILS_MASTER_KEY"] = <value from secrets manager>
# Never use .env files in production — use the platform's secret management.
```

#### Example 8: Weak `secret_key_base` or Hardcoded Secret

**Source:** https://guides.rubyonrails.org/security.html#session-storage
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/environments/production.rb or config/secrets.yml
# VULNERABLE: secret_key_base is a weak, guessable value or is hardcoded
# in source code. This key encrypts session cookies and signed tokens.
# An attacker with this value can forge session cookies and impersonate
# any user — including admins.
Rails.application.configure do
  config.secret_key_base = "aprs-platform-secret"
end

# Or in an initializer:
Rails.application.config.secret_key_base = ENV.fetch("SECRET_KEY_BASE", "fallback-secret")
# The fallback means if ENV is unset, a weak default is used silently.
```

**Secure Fix:**
```ruby
# config/environments/production.rb
# SECURE: secret_key_base comes from credentials.yml.enc (encrypted) or
# from ENV with NO fallback. If the value is missing, the app crashes on boot
# rather than running with a weak secret.
Rails.application.configure do
  # Rails 8.1 reads secret_key_base from credentials by default.
  # If using ENV override, do NOT provide a fallback:
  config.secret_key_base = ENV.fetch("SECRET_KEY_BASE")
  # Raises KeyError if not set — fail-safe rather than fail-open
end

# Generate a strong secret_key_base:
# bin/rails secret
# => "a3f8b1c9d7e2f4a6b0c8d5e1f7a3b9c6d2e8f4a0b7c3d9e5f1a6b2c8d4e0f7..."
# Store in credentials: bin/rails credentials:edit
# secret_key_base: <paste generated value>
```

#### Example 9: TLS Certificate Verification Disabled for Outbound Requests

**Source:** CVE-2014-9490 (Ruby net/http verify_mode bypass — general class of vulnerability)
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/services/weather_enrichment_service.rb
# VULNERABLE: SSL verification is disabled for outbound HTTP calls to the
# weather API. A man-in-the-middle attacker can intercept API keys and
# inject false weather data into sighting records.
class WeatherEnrichmentService
  def fetch_conditions(latitude:, longitude:, observed_at:)
    uri = URI("https://api.weather.example.com/v1/history")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # Disables certificate validation

    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = "Bearer #{ENV['WEATHER_API_KEY']}"
    request["Accept"] = "application/json"

    response = http.request(request)
    JSON.parse(response.body)
  end
end
```

**Secure Fix:**
```ruby
# app/services/weather_enrichment_service.rb
# SECURE: TLS certificate verification is enabled (Ruby default when using
# URI.open or Net::HTTP properly). API key comes from encrypted credentials.
class WeatherEnrichmentService
  TIMEOUT_SECONDS = 10

  # @param latitude [Float] observation latitude
  # @param longitude [Float] observation longitude
  # @param observed_at [Time] observation timestamp
  # @return [Hash] weather conditions at the observation time and location
  # @raise [WeatherEnrichmentError] if the API request fails
  def fetch_conditions(latitude:, longitude:, observed_at:)
    uri = URI("https://api.weather.example.com/v1/history")
    uri.query = URI.encode_www_form(
      lat: latitude,
      lon: longitude,
      dt: observed_at.to_i
    )

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER  # Default, but explicit
    http.open_timeout = TIMEOUT_SECONDS
    http.read_timeout = TIMEOUT_SECONDS

    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = "Bearer #{api_key}"
    request["Accept"] = "application/json"

    response = http.request(request)

    unless response.is_a?(Net::HTTPSuccess)
      raise WeatherEnrichmentError, "Weather API returned #{response.code}"
    end

    JSON.parse(response.body)
  rescue Net::OpenTimeout, Net::ReadTimeout, JSON::ParserError => e
    raise WeatherEnrichmentError, "Weather API error: #{e.message}"
  end

  private

  # @return [String] the weather API key from encrypted credentials
  def api_key
    Rails.application.credentials.dig(:weather_api, :key) ||
      raise(WeatherEnrichmentError, "Weather API key not configured")
  end
end
```

#### Example 10: Timing Attack on API Key Comparison

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/base_controller.rb
# VULNERABLE: Direct string comparison (==) of API keys is susceptible to
# timing attacks. An attacker can determine the correct key one character at
# a time by measuring response time differences. This is especially dangerous
# if keys are not hashed before comparison.
class Api::V1::BaseController < ActionController::API
  private

  def authenticate_api_key!
    provided_key = request.headers["X-API-Key"]
    api_key = ApiKey.find_by(user_id: params[:user_id])

    if api_key && api_key.key == provided_key  # Timing-vulnerable comparison
      @current_api_key = api_key
    else
      head :unauthorized
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/base_controller.rb
# SECURE: Hash the provided key with SHA256 and look up by digest. The database
# query is constant-time with respect to the key value (index lookup). No
# string comparison of raw keys ever occurs. Even if an attacker can measure
# response times, they learn nothing about the key.
class Api::V1::BaseController < ActionController::API
  include Pundit::Authorization

  private

  # @return [void]
  def authenticate_api_key!
    provided_key = request.headers["X-API-Key"]
    return head(:unauthorized) if provided_key.blank?

    # SHA256 digest comparison via database index — constant-time lookup
    digest = Digest::SHA256.hexdigest(provided_key)
    @current_api_key = ApiKey.active.find_by(key_digest: digest)
    return head(:unauthorized) unless @current_api_key

    @current_api_key.touch(:last_used_at)
  end
end

# Alternative for cases where you MUST compare strings directly
# (e.g., webhook signature comparison):
# Use ActiveSupport::SecurityUtils.secure_compare which is constant-time.
#
# Example:
#   ActiveSupport::SecurityUtils.secure_compare(
#     computed_signature,
#     provided_signature
#   )
```

## Checklist

- [ ] Devise `config.stretches` is 12 or higher in production (1 only in test environment)
- [ ] Devise `config.paranoid` is set to `true` (prevents user enumeration)
- [ ] Devise `config.password_length` minimum is 12 characters
- [ ] Devise `config.lock_strategy` is `:failed_attempts` with `maximum_attempts = 5`
- [ ] API keys are stored as SHA256 digests — never plaintext
- [ ] API key plaintext is returned only once on creation and never stored
- [ ] API key authentication uses digest lookup, not string comparison
- [ ] Stripe webhook handler calls `Stripe::Webhook.construct_event` with the webhook signing secret
- [ ] Stripe webhook handler rescues `Stripe::SignatureVerificationError` and returns 400
- [ ] `force_ssl` is `true` in `config/environments/production.rb`
- [ ] HSTS header is configured with `expires >= 1.year`, `subdomains: true`
- [ ] `config/master.key` is in `.gitignore` and never committed
- [ ] `config/credentials/*.key` is in `.gitignore`
- [ ] Witness `contact_info` uses `encrypts :contact_info` (Active Record Encryption)
- [ ] Active Record Encryption keys are stored in `credentials.yml.enc`, not hardcoded
- [ ] `config.filter_parameters` includes: password, token, key, api_key, secret, stripe, name, first_name, last_name, contact_info, phone, email, latitude, longitude
- [ ] No PII (names, contact info, coordinates) appears in `Rails.logger` output
- [ ] Structured logging uses only non-sensitive identifiers (IDs, event types, timestamps)
- [ ] `secret_key_base` is generated via `bin/rails secret` and stored in credentials, never hardcoded
- [ ] No `ENV.fetch` with weak fallback defaults for cryptographic secrets
- [ ] Outbound HTTP connections use `OpenSSL::SSL::VERIFY_PEER` (never `VERIFY_NONE`)
- [ ] API credentials for external services (weather, deconfliction) come from `credentials.yml.enc`
- [ ] Session cookies are configured with `secure: true`, `httponly: true`, `same_site: :lax`
