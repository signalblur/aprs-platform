# A04 — Insecure Design

## Overview

Insecure Design (OWASP 2021 A04, 2025 A06) refers to weaknesses that stem from missing or ineffective security controls at the architecture and design level, rather than from implementation bugs. Unlike implementation flaws that can be fixed with better code, insecure design requires rethinking the system's threat model, trust boundaries, and control flow. No amount of perfect implementation can fix a fundamentally insecure design.

For APRS, insecure design is a critical concern because the platform handles sensitive observational data (UAP sighting reports), processes financial transactions (Stripe subscriptions), manages role-based investigation workflows, and accepts file uploads from partially trusted or anonymous users. The progressive disclosure sighting submission form, the anonymous submission pathway, the deconfliction pipeline, and the Stripe webhook processing flow all represent trust boundaries where design-level security controls must be explicitly architected.

The platform's multi-tier membership model (free, professional, institutional) combined with role-based access control (member, investigator, admin) creates a complex authorization matrix that must be enforced by design, not merely by checking permissions at individual endpoints. Race conditions in webhook processing, missing rate limits on submission endpoints, and business logic flaws in tier enforcement can all lead to data exfiltration, financial loss, or unauthorized access to investigation data.

## APRS-Specific Attack Surface

- **Sighting submission flow**: Progressive disclosure form allows multi-step submission; incomplete validation between steps can allow malformed or malicious data to persist
- **Anonymous submission**: Sightings may be submitted without authentication; design must prevent abuse (spam, data poisoning) without requiring login
- **Investigation assignment logic**: Investigators are assigned to sightings based on geography and availability; flawed assignment logic can leak location data or allow self-assignment
- **Membership tier enforcement**: Premium features (advanced search, API access, bulk export) gated by Stripe subscription tier; tier checks must be centralized, not scattered
- **API rate limiting design**: API keys have monthly quotas; design must prevent quota bypass via key rotation, parallel requests, or response caching abuse
- **Deconfliction pipeline trust model**: External data sources (FAA, weather APIs) are correlated with sightings; pipeline must not trust external data for authorization decisions
- **Stripe webhook processing flow**: Webhooks trigger membership state changes; race conditions and replay attacks can corrupt membership state
- **Evidence upload pipeline**: Users upload photos, videos, and documents as evidence; the pipeline must validate content type, enforce size limits, and quarantine uploads before association with sightings

## Examples

### Basic Level

#### Example 1: Missing Rate Limiting on Sighting Submissions

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/sightings_controller.rb
# No rate limiting — an attacker can flood the system with fake sightings,
# polluting the dataset and consuming storage/database resources.
class SightingsController < ApplicationController
  before_action :authenticate_user!, except: [:create] # anonymous allowed

  def create
    @sighting = Sighting.new(sighting_params)
    @sighting.user = current_user # nil for anonymous
    authorize @sighting

    if @sighting.save
      redirect_to @sighting, notice: "Sighting reported."
    else
      render :new, status: :unprocessable_entity
    end
  end

  private

  def sighting_params
    params.require(:sighting).permit(:title, :description, :observed_at,
                                     :observed_timezone, :latitude, :longitude)
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/sightings_controller.rb
# Rate limiting enforced at the design level using Rack::Attack.
# Anonymous submissions are more aggressively throttled than authenticated ones.
class SightingsController < ApplicationController
  before_action :authenticate_user!, except: [:create]

  def create
    @sighting = Sighting.new(sighting_params)
    @sighting.user = current_user
    @sighting.submitted_ip = request.remote_ip # track for rate limiting
    authorize @sighting

    if @sighting.save
      AuditLog.record!(action: "sighting.created", actor: current_user,
                       resource: @sighting, ip: request.remote_ip)
      redirect_to @sighting, notice: "Sighting reported."
    else
      render :new, status: :unprocessable_entity
    end
  end

  private

  def sighting_params
    params.require(:sighting).permit(:title, :description, :observed_at,
                                     :observed_timezone, :latitude, :longitude)
  end
end

# config/initializers/rack_attack.rb
# Design-level rate limiting using Rack::Attack. Limits are enforced before
# the request reaches the controller, preventing resource exhaustion.
Rack::Attack.throttle("sightings/ip", limit: 5, period: 1.hour) do |req|
  req.ip if req.path == "/sightings" && req.post?
end

Rack::Attack.throttle("sightings/user", limit: 20, period: 1.hour) do |req|
  if req.path == "/sightings" && req.post?
    req.env["warden"]&.user&.id
  end
end

Rack::Attack.throttle("sightings/anonymous", limit: 2, period: 1.hour) do |req|
  if req.path == "/sightings" && req.post? && req.env["warden"]&.user.nil?
    req.ip
  end
end
```

#### Example 2: Insecure Direct Object Reference in Investigation Access

**Source:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/investigations_controller.rb
# Design flaw: investigation lookup uses sequential integer IDs that are
# guessable. Even with authorization checks, the predictable ID scheme
# leaks information about the total number of investigations.
class InvestigationsController < ApplicationController
  before_action :authenticate_user!

  def show
    @investigation = Investigation.find(params[:id]) # sequential integer ID
    authorize @investigation
  end
end
```

**Secure Fix:**
```ruby
# app/models/investigation.rb
# Design fix: use UUIDs as primary keys for investigations to prevent
# enumeration attacks. This is a design-level decision, not an implementation fix.
class Investigation < ApplicationRecord
  self.implicit_order_column = "created_at"

  # UUID primary key configured in migration:
  # create_table :investigations, id: :uuid do |t| ...

  belongs_to :sighting
  belongs_to :investigator, class_name: "User"
  has_many :evidence_items, class_name: "Evidence", dependent: :destroy

  # @param user [User] the user requesting access
  # @return [Boolean] whether the user can access this investigation
  def accessible_by?(user)
    investigator == user || user.admin?
  end
end

# app/controllers/investigations_controller.rb
# Controller uses UUID lookup which is not enumerable.
class InvestigationsController < ApplicationController
  before_action :authenticate_user!

  def show
    @investigation = Investigation.find(params[:id]) # UUID, not sequential
    authorize @investigation
  end
end

# db/migrate/XXXXXX_create_investigations.rb
class CreateInvestigations < ActiveRecord::Migration[8.1]
  def change
    create_table :investigations, id: :uuid do |t|
      t.references :sighting, null: false, foreign_key: true, type: :uuid
      t.references :investigator, null: false, foreign_key: { to_table: :users }, type: :uuid
      t.text :findings
      t.string :status, null: false, default: "open"
      t.timestamps
    end
  end
end
```

#### Example 3: Missing Input Validation at Design Level for Geospatial Data

**Source:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/sighting.rb
# Design flaw: no validation that coordinates are physically plausible.
# An attacker can submit coordinates in the ocean, in restricted airspace,
# or at (0,0) "Null Island" to pollute geospatial queries.
class Sighting < ApplicationRecord
  validates :latitude, presence: true, numericality: true
  validates :longitude, presence: true, numericality: true
  validates :observed_at, presence: true
end
```

**Secure Fix:**
```ruby
# app/models/sighting.rb
# Design fix: validate coordinates are within plausible geographic bounds
# and that observed_at is not in the future. Business logic validation
# belongs in the model as a design constraint.
class Sighting < ApplicationRecord
  LATITUDE_RANGE = (-90.0..90.0).freeze
  LONGITUDE_RANGE = (-180.0..180.0).freeze

  validates :latitude, presence: true,
            numericality: { greater_than_or_equal_to: LATITUDE_RANGE.first,
                            less_than_or_equal_to: LATITUDE_RANGE.last }
  validates :longitude, presence: true,
            numericality: { greater_than_or_equal_to: LONGITUDE_RANGE.first,
                            less_than_or_equal_to: LONGITUDE_RANGE.last }
  validates :observed_at, presence: true
  validate :observed_at_not_in_future
  validate :coordinates_not_null_island

  private

  # @return [void]
  # @raise [ActiveModel::ValidationError] if observed_at is in the future
  def observed_at_not_in_future
    return if observed_at.blank?

    if observed_at > Time.current
      errors.add(:observed_at, "cannot be in the future")
    end
  end

  # @return [void]
  # @raise [ActiveModel::ValidationError] if coordinates are at Null Island
  def coordinates_not_null_island
    if latitude&.zero? && longitude&.zero?
      errors.add(:base, "coordinates appear to be at Null Island (0,0), please verify")
    end
  end
end
```

### Intermediate Level

#### Example 4: Business Logic Flaw in Membership Tier Enforcement

**Source:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/sightings_controller.rb
# Design flaw: tier check is done inline in the controller using a cached
# value from the user record. If the membership is downgraded via Stripe
# webhook while the user is mid-session, the stale tier allows access to
# premium features.
class Api::V1::SightingsController < Api::V1::BaseController
  def export
    authorize Sighting

    # BUG: reads tier from user record, which may be stale
    if current_user.tier == "professional"
      sightings = policy_scope(Sighting).where(export_params)
      render json: sightings
    else
      render json: { error: "Upgrade required" }, status: :forbidden
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/sightings_controller.rb
# Design fix: always check the canonical membership record with a fresh
# database read. Tier is determined by the Membership model, never cached
# on User. This is a design principle, not just a code fix.
class Api::V1::SightingsController < Api::V1::BaseController
  def export
    authorize Sighting

    membership = current_user.active_membership # fresh DB read
    unless membership&.tier_allows?(:bulk_export)
      render json: { error: "Upgrade to Professional tier required" },
             status: :forbidden
      return
    end

    sightings = policy_scope(Sighting).where(export_params)
    render json: sightings
  end
end

# app/models/membership.rb
# Membership is the single source of truth for tier entitlements.
# This centralizes business logic instead of scattering tier checks.
class Membership < ApplicationRecord
  belongs_to :user

  TIER_FEATURES = {
    "free"           => %i[basic_search view_sightings submit_sighting],
    "professional"   => %i[basic_search view_sightings submit_sighting
                           advanced_search bulk_export api_access],
    "institutional"  => %i[basic_search view_sightings submit_sighting
                           advanced_search bulk_export api_access
                           team_management raw_data_export]
  }.freeze

  # @param feature [Symbol] the feature to check access for
  # @return [Boolean] whether the current tier includes the feature
  def tier_allows?(feature)
    return false unless active?

    TIER_FEATURES.fetch(tier, []).include?(feature)
  end

  # @return [Boolean] whether the membership is currently active
  def active?
    status == "active" && (expires_at.nil? || expires_at > Time.current)
  end
end
```

#### Example 5: Race Condition in Stripe Webhook Processing

**Source:** https://stripe.com/docs/webhooks/best-practices
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
# Design flaw: no idempotency check, no pessimistic locking. If Stripe
# sends the same event twice (which is documented behavior), the membership
# could be double-upgraded or the state could become inconsistent.
class Webhooks::StripeController < ApplicationController
  skip_before_action :verify_authenticity_token
  skip_after_action :verify_authorized

  def create
    payload = request.body.read
    sig_header = request.env["HTTP_STRIPE_SIGNATURE"]
    event = Stripe::Webhook.construct_event(payload, sig_header, webhook_secret)

    case event.type
    when "customer.subscription.updated"
      subscription = event.data.object
      user = User.find_by(stripe_customer_id: subscription.customer)
      # BUG: no lock, no idempotency check, trusts webhook payload
      user.membership.update!(
        tier: subscription.items.data.first.price.lookup_key,
        status: subscription.status
      )
    end

    head :ok
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
# Design fix: verify signature, check idempotency via stored event IDs,
# re-fetch from Stripe API (never trust payload), use pessimistic locking.
class Webhooks::StripeController < ApplicationController
  skip_before_action :verify_authenticity_token
  skip_after_action :verify_authorized # justified: webhook auth via Stripe signature

  def create
    payload = request.body.read
    sig_header = request.env["HTTP_STRIPE_SIGNATURE"]

    begin
      event = Stripe::Webhook.construct_event(payload, sig_header, webhook_secret)
    rescue JSON::ParserError, Stripe::SignatureVerificationError => e
      Rails.logger.warn("Stripe webhook signature verification failed",
                        error: e.message)
      head :bad_request
      return
    end

    # Idempotency: skip already-processed events
    if StripeWebhookEvent.exists?(stripe_event_id: event.id)
      head :ok
      return
    end

    StripeWebhookEvent.create!(stripe_event_id: event.id, event_type: event.type)

    case event.type
    when "customer.subscription.updated"
      HandleSubscriptionUpdatedJob.perform_later(event.id)
    end

    head :ok
  end

  private

  # @return [String] the Stripe webhook endpoint secret
  def webhook_secret
    Rails.application.credentials.dig(:stripe, :webhook_secret)
  end
end

# app/jobs/handle_subscription_updated_job.rb
# Background job re-fetches from Stripe API and uses pessimistic locking
# to prevent race conditions on concurrent webhook deliveries.
class HandleSubscriptionUpdatedJob < ApplicationJob
  queue_as :webhooks

  # @param stripe_event_id [String] the Stripe event ID to process
  # @return [void]
  def perform(stripe_event_id)
    event = Stripe::Event.retrieve(stripe_event_id) # re-fetch from API
    subscription = Stripe::Subscription.retrieve(event.data.object.id)

    user = User.find_by!(stripe_customer_id: subscription.customer)

    user.membership.with_lock do # pessimistic lock
      user.membership.update!(
        tier: map_price_to_tier(subscription),
        status: subscription.status,
        stripe_subscription_id: subscription.id,
        current_period_end: Time.zone.at(subscription.current_period_end)
      )
    end

    AuditLog.record!(
      action: "membership.updated_via_webhook",
      actor: nil,
      resource: user.membership,
      metadata: { stripe_event_id: stripe_event_id, new_tier: user.membership.tier }
    )
  end

  private

  # @param subscription [Stripe::Subscription] the Stripe subscription object
  # @return [String] the APRS tier name
  def map_price_to_tier(subscription)
    lookup_key = subscription.items.data.first.price.lookup_key
    Membership::STRIPE_TIER_MAP.fetch(lookup_key) do
      raise "Unknown Stripe price lookup_key: #{lookup_key}"
    end
  end
end
```

#### Example 6: Trust Boundary Violation Between API and Web Controllers

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/base_controller.rb
# Design flaw: API controller inherits from ApplicationController which
# has CSRF protection. Simply skipping CSRF without adding API-specific
# authentication creates an unauthenticated endpoint.
class Api::V1::BaseController < ApplicationController
  skip_before_action :verify_authenticity_token
  # Missing: no API authentication mechanism at all!
end

# app/controllers/api/v1/sightings_controller.rb
class Api::V1::SightingsController < Api::V1::BaseController
  def index
    # No authentication, no rate limiting, no quota tracking
    @sightings = policy_scope(Sighting)
    render json: @sightings
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/base_controller.rb
# Design fix: API controllers form a separate trust boundary. They skip
# CSRF (appropriate for API) but enforce API key authentication, rate
# limiting, and quota tracking as design-level controls.
class Api::V1::BaseController < ActionController::API
  include Pundit::Authorization

  before_action :authenticate_api_key!
  before_action :enforce_rate_limit!
  after_action :verify_authorized
  after_action :track_api_usage

  private

  # @return [User] the authenticated user
  # @raise [UnauthorizedError] if API key is missing or invalid
  def authenticate_api_key!
    token = request.headers["X-API-Key"]
    if token.blank?
      render json: { error: "API key required" }, status: :unauthorized
      return
    end

    key_digest = Digest::SHA256.hexdigest(token)
    @api_key = ApiKey.includes(:user).find_by(key_digest: key_digest)

    if @api_key.nil? || @api_key.revoked?
      render json: { error: "Invalid API key" }, status: :unauthorized
      return
    end

    @current_user = @api_key.user
  end

  # @return [void]
  def enforce_rate_limit!
    return if @api_key.nil?

    if @api_key.monthly_requests_used >= @api_key.monthly_quota
      render json: { error: "Monthly API quota exceeded",
                     quota: @api_key.monthly_quota,
                     used: @api_key.monthly_requests_used },
             status: :too_many_requests
    end
  end

  # @return [void]
  def track_api_usage
    return if @api_key.nil?

    @api_key.increment!(:monthly_requests_used)
  end

  # @return [User, nil] the current API user
  def current_user
    @current_user
  end
end
```

### Advanced Level

#### Example 7: Deconfliction Pipeline Trust Model Violation

**Source:** https://owasp.org/www-community/Threat_Modeling
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/deconfliction_service.rb
# Design flaw: the deconfliction pipeline trusts external API responses
# to determine sighting classification. An attacker who can influence
# FAA or weather API responses (DNS hijack, MITM) can cause sightings
# to be auto-classified as "explained" and hidden from investigators.
class DeconflictionService
  # @param sighting [Sighting] the sighting to deconflict
  # @return [DeconflictionResult]
  def call(sighting)
    faa_data = FaaApiClient.flights_near(
      lat: sighting.latitude, lon: sighting.longitude,
      time: sighting.observed_at, radius_nm: 10
    )

    weather = WeatherApiClient.conditions_at(
      lat: sighting.latitude, lon: sighting.longitude,
      time: sighting.observed_at
    )

    # BUG: auto-classifies based solely on external data
    if faa_data[:matches].any?
      sighting.update!(status: "explained", explanation: "Matched FAA flight")
      return DeconflictionResult.create!(sighting: sighting, result: "explained")
    end

    DeconflictionResult.create!(sighting: sighting, result: "unresolved")
  end
end
```

**Secure Fix:**
```ruby
# app/services/deconfliction_service.rb
# Design fix: external data is treated as advisory, never authoritative.
# Results are stored as correlations for human review, not used to
# auto-classify sightings. The trust boundary is explicit: external data
# informs but never decides.
class DeconflictionService
  CONFIDENCE_THRESHOLD = 0.85

  # @param sighting [Sighting] the sighting to deconflict
  # @return [DeconflictionResult]
  def call(sighting)
    faa_data = fetch_with_validation(:faa, sighting)
    weather_data = fetch_with_validation(:weather, sighting)

    correlations = build_correlations(sighting, faa_data, weather_data)

    DeconflictionResult.create!(
      sighting: sighting,
      result: "pending_review", # never auto-classify
      faa_correlations: correlations[:faa],
      weather_correlations: correlations[:weather],
      confidence_score: correlations[:confidence],
      raw_responses_digest: digest_responses(faa_data, weather_data)
    )
    # Sighting status remains "under_review" until an investigator decides
  end

  private

  # @param source [Symbol] the external data source
  # @param sighting [Sighting] the sighting to query for
  # @return [Hash] validated external data
  def fetch_with_validation(source, sighting)
    case source
    when :faa
      data = FaaApiClient.flights_near(
        lat: sighting.latitude, lon: sighting.longitude,
        time: sighting.observed_at, radius_nm: 10
      )
      validate_faa_response!(data)
      data
    when :weather
      data = WeatherApiClient.conditions_at(
        lat: sighting.latitude, lon: sighting.longitude,
        time: sighting.observed_at
      )
      validate_weather_response!(data)
      data
    end
  rescue ExternalApiError => e
    Rails.logger.warn("Deconfliction external API error",
                      source: source, sighting_id: sighting.id, error: e.message)
    { matches: [], error: e.message }
  end

  # @param data [Hash] raw FAA response
  # @return [void]
  # @raise [ExternalApiError] if response structure is unexpected
  def validate_faa_response!(data)
    unless data.is_a?(Hash) && data.key?(:matches) && data[:matches].is_a?(Array)
      raise ExternalApiError, "Unexpected FAA API response structure"
    end
  end

  # @param data [Hash] raw weather response
  # @return [void]
  # @raise [ExternalApiError] if response structure is unexpected
  def validate_weather_response!(data)
    unless data.is_a?(Hash) && data.key?(:conditions)
      raise ExternalApiError, "Unexpected Weather API response structure"
    end
  end

  # @param faa_data [Hash] FAA response data
  # @param weather_data [Hash] weather response data
  # @return [String] SHA256 digest of raw responses for audit trail
  def digest_responses(*responses)
    Digest::SHA256.hexdigest(responses.map(&:to_json).join("|"))
  end

  # @param sighting [Sighting] the sighting
  # @param faa_data [Hash] FAA correlations
  # @param weather_data [Hash] weather correlations
  # @return [Hash] structured correlation data
  def build_correlations(sighting, faa_data, weather_data)
    {
      faa: faa_data[:matches] || [],
      weather: weather_data[:conditions] || {},
      confidence: calculate_confidence(faa_data, weather_data)
    }
  end

  # @param faa_data [Hash] FAA correlation data
  # @param weather_data [Hash] weather correlation data
  # @return [Float] confidence score between 0.0 and 1.0
  def calculate_confidence(faa_data, weather_data)
    score = 0.0
    score += 0.5 if faa_data[:matches]&.any?
    score += 0.3 if weather_data.dig(:conditions, :visibility) == "poor"
    score.clamp(0.0, 1.0)
  end
end
```

#### Example 8: Evidence Upload Pipeline Without Content Validation

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/evidence_controller.rb
# Design flaw: file uploads are accepted based only on file extension.
# An attacker can upload a PHP web shell with a .jpg extension, or an
# SVG file containing embedded JavaScript for stored XSS.
class EvidenceController < ApplicationController
  before_action :authenticate_user!

  def create
    @evidence = Evidence.new(evidence_params)
    @evidence.investigation = Investigation.find(params[:investigation_id])
    authorize @evidence

    if @evidence.save
      redirect_to @evidence.investigation, notice: "Evidence uploaded."
    else
      render :new, status: :unprocessable_entity
    end
  end

  private

  def evidence_params
    params.require(:evidence).permit(:file, :description, :evidence_type)
  end
end

# app/models/evidence.rb
class Evidence < ApplicationRecord
  has_one_attached :file
  # No content type validation, no size limit, no magic byte check
end
```

**Secure Fix:**
```ruby
# app/models/evidence.rb
# Design fix: enforce content validation at the model level as a design
# constraint. Validate both declared content type and actual file magic
# bytes. Enforce size limits. Quarantine before association.
class Evidence < ApplicationRecord
  has_one_attached :file

  belongs_to :investigation
  belongs_to :uploader, class_name: "User"

  ALLOWED_CONTENT_TYPES = %w[
    image/jpeg image/png image/webp
    video/mp4 video/quicktime
    application/pdf
  ].freeze

  MAX_FILE_SIZE = 100.megabytes

  validates :file, presence: true
  validate :acceptable_file

  after_create_commit :schedule_virus_scan

  private

  # @return [void]
  def acceptable_file
    return unless file.attached?

    unless file.blob.byte_size <= MAX_FILE_SIZE
      errors.add(:file, "is too large (maximum is #{MAX_FILE_SIZE / 1.megabyte}MB)")
    end

    unless ALLOWED_CONTENT_TYPES.include?(file.blob.content_type)
      errors.add(:file, "must be a JPEG, PNG, WebP, MP4, MOV, or PDF")
    end
  end

  # @return [void]
  def schedule_virus_scan
    EvidenceVirusScanJob.perform_later(id)
  end
end

# app/services/file_content_validator.rb
# Validates file content by checking magic bytes, not just the declared
# content type. This prevents extension spoofing attacks.
class FileContentValidator
  MAGIC_BYTES = {
    "image/jpeg" => ["\xFF\xD8\xFF".b],
    "image/png"  => ["\x89PNG\r\n\x1A\n".b],
    "image/webp" => ["RIFF".b], # followed by size then "WEBP"
    "video/mp4"  => ["ftyp".b], # at offset 4
    "application/pdf" => ["%PDF".b]
  }.freeze

  # @param blob [ActiveStorage::Blob] the blob to validate
  # @return [Boolean] whether the file content matches its declared type
  def self.valid?(blob)
    declared_type = blob.content_type
    return false unless MAGIC_BYTES.key?(declared_type)

    blob.open do |tempfile|
      header = tempfile.read(16)
      return false if header.nil?

      MAGIC_BYTES[declared_type].any? { |magic| header.include?(magic) }
    end
  end
end

# app/jobs/evidence_virus_scan_job.rb
# Quarantine pattern: file is not accessible until scan completes.
class EvidenceVirusScanJob < ApplicationJob
  queue_as :evidence_processing

  # @param evidence_id [Integer] the evidence record ID
  # @return [void]
  def perform(evidence_id)
    evidence = Evidence.find(evidence_id)

    unless FileContentValidator.valid?(evidence.file.blob)
      evidence.update!(status: "rejected", rejection_reason: "content_type_mismatch")
      AuditLog.record!(action: "evidence.rejected", resource: evidence,
                       metadata: { reason: "magic_byte_mismatch" })
      return
    end

    evidence.update!(status: "verified")
    AuditLog.record!(action: "evidence.verified", resource: evidence)
  end
end
```

#### Example 9: API Rate Limiting Bypass via Key Rotation

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#rate-limiting
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/api_keys_controller.rb
# Design flaw: users can regenerate API keys without limit. Each new key
# gets a fresh monthly quota, allowing unlimited API usage by rotating keys.
class Api::V1::ApiKeysController < Api::V1::BaseController
  def create
    authorize ApiKey

    old_key = current_user.api_keys.active.last
    old_key&.revoke!

    raw_token = SecureRandom.hex(32)
    @api_key = current_user.api_keys.create!(
      key_digest: Digest::SHA256.hexdigest(raw_token),
      monthly_requests_used: 0 # fresh quota on every rotation!
    )

    render json: { api_key: raw_token, message: "Store this securely" },
           status: :created
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/api_keys_controller.rb
# Design fix: quota is tracked on the User level (via Membership), not on
# individual API keys. Key rotation does not reset the quota. Rate limits
# are also enforced per-user, not per-key.
class Api::V1::ApiKeysController < Api::V1::BaseController
  ROTATION_COOLDOWN = 24.hours

  def create
    authorize ApiKey

    if recent_rotation?
      render json: { error: "API key rotation limited to once per 24 hours" },
             status: :too_many_requests
      return
    end

    raw_token = SecureRandom.hex(32)

    ActiveRecord::Base.transaction do
      current_user.api_keys.active.update_all(
        revoked_at: Time.current,
        revocation_reason: "rotated"
      )

      @api_key = current_user.api_keys.create!(
        key_digest: Digest::SHA256.hexdigest(raw_token),
        # Quota is NOT on the key; it is tracked on the membership
        created_ip: request.remote_ip
      )
    end

    AuditLog.record!(action: "api_key.rotated", actor: current_user,
                     resource: @api_key, ip: request.remote_ip)

    render json: { api_key: raw_token, message: "Store this securely" },
           status: :created
  end

  private

  # @return [Boolean] whether a key was recently rotated
  def recent_rotation?
    current_user.api_keys
                .where("created_at > ?", ROTATION_COOLDOWN.ago)
                .exists?
  end
end

# app/models/membership.rb
# Quota tracking lives on Membership, not on ApiKey.
# This is the design-level fix that prevents quota bypass.
class Membership < ApplicationRecord
  MONTHLY_QUOTAS = {
    "free" => 100,
    "professional" => 10_000,
    "institutional" => 100_000
  }.freeze

  # @return [Integer] the monthly API quota for this membership tier
  def monthly_quota
    MONTHLY_QUOTAS.fetch(tier, 0)
  end

  # @return [Boolean] whether the monthly quota has been exceeded
  def quota_exceeded?
    monthly_api_requests >= monthly_quota
  end

  # @return [void]
  def increment_api_usage!
    increment!(:monthly_api_requests)
  end

  # @return [void]
  def reset_monthly_usage!
    update!(monthly_api_requests: 0, quota_reset_at: Time.current)
  end
end
```

#### Example 10: Investigation Self-Assignment Allows Conflict of Interest

**Source:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Test_for_the_Circumvention_of_Work_Flows
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/investigations_controller.rb
# Design flaw: investigators can assign themselves to any sighting,
# including their own. This creates a conflict of interest where a
# user who submitted a sighting can investigate it themselves.
class InvestigationsController < ApplicationController
  before_action :authenticate_user!

  def create
    @sighting = Sighting.find(params[:sighting_id])
    @investigation = Investigation.new(
      sighting: @sighting,
      investigator: current_user # self-assignment allowed
    )
    authorize @investigation

    if @investigation.save
      redirect_to @investigation, notice: "Investigation started."
    else
      render :new, status: :unprocessable_entity
    end
  end
end
```

**Secure Fix:**
```ruby
# app/models/investigation.rb
# Design fix: business rules prevent self-investigation and enforce
# geographic proximity requirements for field investigators.
class Investigation < ApplicationRecord
  belongs_to :sighting
  belongs_to :investigator, class_name: "User"

  validate :investigator_is_not_reporter
  validate :investigator_has_required_role
  validate :no_duplicate_active_investigation

  private

  # @return [void]
  def investigator_is_not_reporter
    if sighting.user_id.present? && sighting.user_id == investigator_id
      errors.add(:investigator, "cannot investigate their own sighting")
    end
  end

  # @return [void]
  def investigator_has_required_role
    unless investigator&.investigator? || investigator&.admin?
      errors.add(:investigator, "must have investigator or admin role")
    end
  end

  # @return [void]
  def no_duplicate_active_investigation
    if Investigation.where(sighting: sighting, status: "open")
                    .where.not(id: id)
                    .exists?
      errors.add(:sighting, "already has an active investigation")
    end
  end
end

# app/services/investigation_assignment_service.rb
# Encapsulates the assignment business logic in a service object.
# Assignment is a controlled process, not a free-form action.
class InvestigationAssignmentService
  # @param sighting [Sighting] the sighting to investigate
  # @param requester [User] the user requesting the assignment
  # @param investigator [User] the proposed investigator (may differ from requester)
  # @return [Investigation] the created investigation
  # @raise [Pundit::NotAuthorizedError] if requester lacks permission
  def call(sighting:, requester:, investigator: nil)
    investigator ||= find_best_investigator(sighting)

    investigation = Investigation.new(
      sighting: sighting,
      investigator: investigator,
      assigned_by: requester
    )

    raise Pundit::NotAuthorizedError unless InvestigationPolicy.new(requester, investigation).create?

    investigation.save!

    AuditLog.record!(
      action: "investigation.assigned",
      actor: requester,
      resource: investigation,
      metadata: { investigator_id: investigator.id, sighting_id: sighting.id }
    )

    investigation
  end

  private

  # @param sighting [Sighting] the sighting needing an investigator
  # @return [User] the best available investigator
  def find_best_investigator(sighting)
    User.where(role: :investigator)
        .where.not(id: sighting.user_id) # exclude reporter
        .joins(:investigator_profile)
        .merge(InvestigatorProfile.available)
        .order(
          Arel.sql(
            "ST_Distance(investigator_profiles.location, " \
            "ST_SetSRID(ST_MakePoint(#{sighting.longitude}, #{sighting.latitude}), 4326)::geography)"
          )
        )
        .first || raise("No available investigators found")
  end
end
```

## Checklist

- [ ] All submission endpoints (sighting, evidence, witness report) have rate limiting configured in Rack::Attack
- [ ] Anonymous submission endpoints have stricter rate limits than authenticated ones
- [ ] UUIDs are used as primary keys for sensitive resources (Investigation, Evidence, Sighting)
- [ ] Geospatial input validation rejects impossible coordinates and Null Island
- [ ] `observed_at` is validated to prevent future dates
- [ ] Membership tier is always checked via `Membership#tier_allows?`, never via a cached or duplicated field on User
- [ ] Stripe webhook events are recorded in `StripeWebhookEvent` for idempotency
- [ ] Stripe webhook handler re-fetches data from Stripe API, never trusts the payload directly
- [ ] Membership updates from webhooks use `with_lock` (pessimistic locking)
- [ ] API controllers inherit from `ActionController::API`, not `ApplicationController`
- [ ] API authentication uses SHA256-digested API keys, not raw tokens in the database
- [ ] API quota is tracked on Membership, not on individual API keys
- [ ] API key rotation has a cooldown period and does not reset quota
- [ ] Deconfliction pipeline treats external API data as advisory, never auto-classifies sightings
- [ ] External API responses are validated for expected structure before processing
- [ ] Evidence uploads validate both declared content type and magic bytes
- [ ] Evidence files are quarantined until virus/content scan completes
- [ ] File size limits are enforced at the model level
- [ ] Investigation self-assignment is prevented (reporter cannot be investigator)
- [ ] Investigation assignment requires investigator or admin role
- [ ] All design decisions affecting security are documented with threat model rationale
- [ ] AuditLog records are created for all security-relevant state transitions
