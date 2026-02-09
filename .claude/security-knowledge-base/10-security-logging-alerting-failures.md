# A10 — Security Logging and Alerting Failures

## Overview

Security Logging and Alerting Failures (OWASP 2021 A09, 2025 A09) occur when an application fails to detect, escalate, or alert on active attacks in a timely manner. Insufficient logging, ineffective log monitoring, and missing alerting mechanisms allow attackers to operate undetected, pivot deeper into systems, tamper with data, or exfiltrate sensitive information without triggering any response.

For the APRS platform, this risk is particularly acute because the system handles multiple categories of sensitive data: witness personally identifiable information (PII) such as names, emails, phone numbers, and physical addresses; precise geospatial coordinates that could identify observer locations; API keys for third-party integrations; Stripe payment tokens and subscription details; and investigation case data that may have legal sensitivity. The platform also integrates with 13 external enrichment and deconfliction APIs, each of which generates log-worthy events that must be captured without leaking credentials or PII.

Rails applications are especially susceptible to logging failures because `Rails.logger` defaults to unstructured text output, ActiveRecord query logging can inadvertently include sensitive column values, and Devise authentication events require explicit configuration to capture. Without structured JSON logging, centralized log aggregation, and explicit PII scrubbing, the APRS platform risks both compliance violations (leaking PII into log storage) and security blind spots (failing to detect brute-force attacks, unauthorized access, or data tampering).

## APRS-Specific Attack Surface

- **Rails.logger configuration**: Default text-format logging lacks structured fields needed for SIEM ingestion and automated alerting
- **PII in logs**: Witness contact info (email, phone, address), user emails, precise coordinates, and API keys can leak into request/query logs
- **Audit log completeness**: The `AuditLog` model must capture all security-relevant events including authorization failures, data modifications, and admin actions
- **Failed login attempt logging**: Devise lockable tracks failed attempts in the database but may not emit log events for external monitoring
- **API key usage tracking**: `ApiKey` usage, quota consumption, and abuse patterns must be logged without exposing the key value
- **Stripe webhook event logging**: `StripeWebhookEvent` processing must be logged for idempotency auditing without leaking payment details
- **Sighting modification history**: Changes to `Sighting` records must maintain an audit trail for investigation integrity
- **Missing alerting on security events**: No alerting pipeline means brute-force login attempts, privilege escalation, and API abuse go undetected
- **Log injection attacks**: User-supplied input (sighting descriptions, witness names) can inject fake log entries or corrupt log parsers
- **Sensitive parameter filtering**: Rails `filter_parameters` must cover all sensitive fields across all models

## Examples

### Basic Level

#### Example 1: PII Leaking Into Logs via Unfiltered Parameters

**Source:** https://guides.rubyonrails.org/configuring.html#config-filter-parameters
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/application.rb
# Only filtering the default Rails parameters
module Aprs
  class Application < Rails::Application
    config.filter_parameters += [:password]
  end
end

# app/controllers/witnesses_controller.rb
class WitnessesController < ApplicationController
  def create
    # Rails logs the full params hash in development AND production
    # if filter_parameters is incomplete
    @witness = Witness.new(witness_params)
    authorize @witness
    if @witness.save
      # Log contains: email, phone, address in plaintext
      Rails.logger.info("Witness created: #{witness_params}")
      redirect_to @witness
    else
      render :new, status: :unprocessable_entity
    end
  end

  private

  def witness_params
    params.require(:witness).permit(:name, :email, :phone, :address,
                                    :city, :state, :zip_code)
  end
end
```

**Secure Fix:**
```ruby
# config/application.rb
# Comprehensive filter list covering all sensitive APRS fields
module Aprs
  class Application < Rails::Application
    config.filter_parameters += [
      :password, :password_confirmation, :token, :key, :secret,
      :stripe, :api_key, :api_key_digest,
      # PII fields
      :email, :phone, :address, :zip_code, :ip,
      # Geospatial PII (precise location can identify observers)
      :latitude, :longitude, :coordinates,
      # Financial
      :card, :account, :routing
    ]
  end
end

# app/controllers/witnesses_controller.rb
class WitnessesController < ApplicationController
  # @param none
  # @return [void]
  # @raise [Pundit::NotAuthorizedError] if user lacks permission
  def create
    @witness = Witness.new(witness_params)
    authorize @witness

    if @witness.save
      # Log only the record ID, never PII
      Rails.logger.info(
        event: "witness.created",
        witness_id: @witness.id,
        user_id: current_user.id
      )
      redirect_to @witness
    else
      render :new, status: :unprocessable_entity
    end
  end

  private

  # @return [ActionController::Parameters] permitted witness attributes
  def witness_params
    params.require(:witness).permit(:name, :email, :phone, :address,
                                    :city, :state, :zip_code)
  end
end
```

#### Example 2: Sensitive Data in ActiveRecord Query Logs

**Source:** https://guides.rubyonrails.org/configuring.html#config-active-record-encryption-add-to-filter-parameters
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# When ActiveRecord logging is enabled, queries with literal values
# expose sensitive data in logs:
#
# User Load (0.5ms)  SELECT "users".* FROM "users"
#   WHERE "users"."email" = 'witness@example.com'
#   AND "users"."api_key_digest" = 'abc123...'
#
# This happens when using find_by or where with literal values:
class Api::V1::BaseController < ApplicationController
  def authenticate_api_key!
    key = request.headers["X-Api-Key"]
    digest = Digest::SHA256.hexdigest(key)
    # The digest value appears in the SQL log
    @api_key = ApiKey.find_by(key_digest: digest, active: true)
  end
end
```

**Secure Fix:**
```ruby
# config/application.rb
module Aprs
  class Application < Rails::Application
    # Filter sensitive values from SQL query logs
    config.active_record.encryption.add_to_filter_parameters = true

    # In production, suppress full SQL in logs
    config.active_record.logger = nil if Rails.env.production?
  end
end

# config/environments/production.rb
Rails.application.configure do
  # Use :info level to avoid debug-level query logging
  config.log_level = :info

  # Tag all log entries with request metadata for correlation
  config.log_tags = [:request_id]
end

# app/controllers/api/v1/base_controller.rb
module Api
  module V1
    class BaseController < ApplicationController
      skip_forgery_protection

      before_action :authenticate_api_key!

      private

      # Authenticate requests via SHA256 API key digest.
      # The raw key is never logged or stored.
      #
      # @return [void]
      # @raise [ActiveRecord::RecordNotFound] if key is invalid
      def authenticate_api_key!
        key = request.headers["X-Api-Key"]
        return head(:unauthorized) if key.blank?

        digest = Digest::SHA256.hexdigest(key)
        @api_key = ApiKey.where(active: true)
                         .find_by!(key_digest: digest)

        Rails.logger.info(
          event: "api.authenticated",
          api_key_id: @api_key.id,
          client_name: @api_key.client_name
        )
      rescue ActiveRecord::RecordNotFound
        Rails.logger.warn(
          event: "api.authentication_failed",
          ip: request.remote_ip
        )
        head :unauthorized
      end
    end
  end
end
```

#### Example 3: Missing Structured Logging Format

**Source:** https://guides.rubyonrails.org/configuring.html#config-log-formatter
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/environments/production.rb
Rails.application.configure do
  # Default Rails text formatter produces unstructured output:
  # I, [2024-01-15T10:30:00.000000 #1234]  INFO -- : Sighting created id=42
  # This is difficult to parse, query, and alert on in log aggregation tools
  config.log_formatter = ::Logger::Formatter.new
end

# app/services/sighting_enrichment_service.rb
class SightingEnrichmentService
  def enrich(sighting)
    Rails.logger.info("Starting enrichment for sighting #{sighting.id}")
    weather = fetch_weather(sighting)
    Rails.logger.info("Weather fetched: #{weather.inspect}")
    # Unstructured text logs cannot be reliably queried
  end
end
```

**Secure Fix:**
```ruby
# config/environments/production.rb
Rails.application.configure do
  # Use structured JSON logging for SIEM/log aggregation compatibility
  config.log_formatter = proc do |severity, timestamp, _progname, msg|
    payload = if msg.is_a?(Hash)
                msg.merge(severity: severity, timestamp: timestamp.utc.iso8601(3))
              else
                { severity: severity, timestamp: timestamp.utc.iso8601(3), message: msg.to_s }
              end
    "#{payload.to_json}\n"
  end

  # Alternatively, use the lograge gem for request-level structured logging
  config.lograge.enabled = true
  config.lograge.formatter = Lograge::Formatters::Json.new
  config.lograge.custom_payload do |controller|
    {
      user_id: controller.current_user&.id,
      request_id: controller.request.request_id
    }
  end
end

# app/services/sighting_enrichment_service.rb
class SightingEnrichmentService
  # Enrich a sighting with external data sources.
  #
  # @param sighting [Sighting] the sighting to enrich
  # @return [void]
  def enrich(sighting)
    Rails.logger.info(
      event: "enrichment.started",
      sighting_id: sighting.id,
      enrichment_sources: %w[weather aircraft satellite]
    )

    weather = fetch_weather(sighting)

    Rails.logger.info(
      event: "enrichment.weather.completed",
      sighting_id: sighting.id,
      weather_source: weather.source,
      conditions_count: weather.conditions.size
    )
  end
end
```

### Intermediate Level

#### Example 4: Missing Audit Trail for Authorization Failures

**Source:** https://github.com/varvet/pundit#rescuing-a-notauthorizederror-in-applicationcontroller
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  include Pundit::Authorization

  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index

  rescue_from Pundit::NotAuthorizedError do |_exception|
    # Silently redirects — no logging of the authorization failure
    flash[:alert] = "You are not authorized to perform this action."
    redirect_back(fallback_location: root_path)
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  include Pundit::Authorization

  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index

  rescue_from Pundit::NotAuthorizedError, with: :handle_unauthorized

  private

  # Handle Pundit authorization failures with logging and audit trail.
  #
  # @param exception [Pundit::NotAuthorizedError] the authorization error
  # @return [void]
  def handle_unauthorized(exception)
    # Structured log for SIEM alerting
    Rails.logger.warn(
      event: "authorization.denied",
      user_id: current_user&.id,
      user_role: current_user&.role,
      policy: exception.policy.class.name,
      query: exception.query,
      record_type: exception.record.class.name,
      record_id: exception.record.respond_to?(:id) ? exception.record.id : nil,
      ip: request.remote_ip,
      path: request.fullpath,
      method: request.method
    )

    # Persist to AuditLog for investigation review
    AuditLog.create!(
      user: current_user,
      action: "authorization_denied",
      resource_type: exception.record.class.name,
      resource_id: exception.record.respond_to?(:id) ? exception.record.id : nil,
      metadata: {
        policy: exception.policy.class.name,
        query: exception.query,
        ip: request.remote_ip,
        path: request.fullpath
      }
    )

    flash[:alert] = "You are not authorized to perform this action."
    redirect_back(fallback_location: root_path)
  end
end
```

#### Example 5: Failed Login Attempts Not Logged for External Monitoring

**Source:** https://github.com/heartcombo/devise/wiki/How-To:-Use-a-custom-strategy
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# Devise lockable tracks failed_attempts in the database,
# but emits no log event that an external SIEM can consume.
# An attacker can brute-force credentials and the only record
# is the counter on the user record itself.

# config/initializers/devise.rb
Devise.setup do |config|
  config.paranoid = true
  config.lock_strategy = :failed_attempts
  config.maximum_attempts = 5
  config.unlock_strategy = :time
  config.unlock_in = 30.minutes
  config.stretches = 12
  # No Warden callback configured for failed auth logging
end
```

**Secure Fix:**
```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  config.paranoid = true
  config.lock_strategy = :failed_attempts
  config.maximum_attempts = 5
  config.unlock_strategy = :time
  config.unlock_in = 30.minutes
  config.stretches = 12
end

# config/initializers/warden_hooks.rb
# Log all authentication events for SIEM consumption.
# Devise paranoid mode ensures we do not reveal whether an email exists.

Warden::Manager.after_authentication do |user, auth, _opts|
  Rails.logger.info(
    event: "auth.login_success",
    user_id: user.id,
    ip: auth.request.remote_ip,
    user_agent: auth.request.user_agent
  )

  AuditLog.create!(
    user: user,
    action: "login_success",
    metadata: { ip: auth.request.remote_ip }
  )
end

Warden::Manager.before_failure do |env, opts|
  request = ActionDispatch::Request.new(env)

  Rails.logger.warn(
    event: "auth.login_failure",
    attempted_scope: opts[:scope],
    ip: request.remote_ip,
    user_agent: request.user_agent,
    failure_reason: opts[:message]
  )

  # Do NOT log the attempted email — paranoid mode means
  # we must not reveal whether the account exists
  AuditLog.create!(
    action: "login_failure",
    metadata: {
      ip: request.remote_ip,
      scope: opts[:scope].to_s,
      reason: opts[:message].to_s
    }
  )
end

Warden::Manager.before_logout do |user, auth, _opts|
  if user
    Rails.logger.info(
      event: "auth.logout",
      user_id: user.id,
      ip: auth.request.remote_ip
    )
  end
end
```

#### Example 6: Log Injection via User-Supplied Input

**Source:** https://owasp.org/www-community/attacks/Log_Injection
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/sightings_controller.rb
class SightingsController < ApplicationController
  def create
    @sighting = current_user.sightings.build(sighting_params)
    authorize @sighting

    if @sighting.save
      # Attacker sets description to:
      # "normal text\n2024-01-15 INFO -- : admin_role_granted user_id=1"
      # This injects a fake log line that could deceive log analysis
      Rails.logger.info("Sighting created: #{@sighting.description}")
      redirect_to @sighting
    else
      render :new, status: :unprocessable_entity
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/sightings_controller.rb
class SightingsController < ApplicationController
  # @return [void]
  # @raise [Pundit::NotAuthorizedError] if user lacks permission
  def create
    @sighting = current_user.sightings.build(sighting_params)
    authorize @sighting

    if @sighting.save
      # NEVER interpolate user input into log messages.
      # Use structured logging with separate fields so user content
      # cannot inject fake log entries or break log parsers.
      Rails.logger.info(
        event: "sighting.created",
        sighting_id: @sighting.id,
        user_id: current_user.id,
        shape: @sighting.shape&.name,
        observed_at: @sighting.observed_at&.iso8601
      )

      AuditLog.create!(
        user: current_user,
        action: "sighting_created",
        resource_type: "Sighting",
        resource_id: @sighting.id,
        metadata: { shape: @sighting.shape&.name }
      )

      redirect_to @sighting
    else
      render :new, status: :unprocessable_entity
    end
  end
end

# lib/log_sanitizer.rb
# If free-text must appear in logs, sanitize it first.
module LogSanitizer
  # Sanitize user-supplied text for safe log inclusion.
  # Removes newlines, carriage returns, and control characters.
  #
  # @param text [String] the raw user input
  # @param max_length [Integer] maximum allowed length (default 200)
  # @return [String] sanitized text safe for log fields
  def self.sanitize(text, max_length: 200)
    return "" if text.nil?

    text.to_s
        .gsub(/[\r\n\t]/, " ")       # Replace newlines/tabs with spaces
        .gsub(/[^[:print:]]/, "")     # Strip non-printable characters
        .truncate(max_length)
  end
end
```

### Advanced Level

#### Example 7: Incomplete Audit Log Coverage for Sighting Modifications

**Source:** https://guides.rubyonrails.org/active_record_callbacks.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/sighting.rb
class Sighting < ApplicationRecord
  belongs_to :user
  belongs_to :shape, optional: true
  has_many :evidences, dependent: :destroy
  has_many :deconfliction_results, dependent: :destroy

  # No audit trail for modifications.
  # An investigator could alter a sighting's coordinates, time,
  # or description with no record of the change.
  # This undermines investigation integrity.
end
```

**Secure Fix:**
```ruby
# app/models/concerns/auditable.rb
# Automatically creates AuditLog entries for security-relevant
# model changes. Captures before/after values for changed attributes
# while filtering sensitive fields.
#
# Usage: include Auditable in any model that requires audit trails.
module Auditable
  extend ActiveSupport::Concern

  FILTERED_ATTRIBUTES = %w[
    password password_digest api_key_digest encrypted_password
    reset_password_token confirmation_token email phone address
  ].freeze

  included do
    after_create  :audit_create
    after_update  :audit_update
    after_destroy :audit_destroy
  end

  private

  # @return [void]
  def audit_create
    create_audit_entry("created", {})
  end

  # @return [void]
  def audit_update
    filtered_changes = saved_changes.except(*FILTERED_ATTRIBUTES, "updated_at")
    return if filtered_changes.empty?

    create_audit_entry("updated", filtered_changes)
  end

  # @return [void]
  def audit_destroy
    create_audit_entry("destroyed", {})
  end

  # @param action [String] the audit action name
  # @param changes [Hash] the attribute changes to record
  # @return [AuditLog]
  def create_audit_entry(action, changes)
    AuditLog.create!(
      user: Current.user,
      action: "#{self.class.name.underscore}.#{action}",
      resource_type: self.class.name,
      resource_id: id,
      metadata: {
        changes: changes,
        ip: Current.ip_address,
        request_id: Current.request_id
      }
    )
  end
end

# app/models/sighting.rb
class Sighting < ApplicationRecord
  include Auditable

  belongs_to :user
  belongs_to :shape, optional: true
  has_many :evidences, dependent: :destroy
  has_many :deconfliction_results, dependent: :destroy
end

# app/models/current.rb
# Thread-safe request context for audit logging.
class Current < ActiveSupport::CurrentAttributes
  attribute :user, :ip_address, :request_id
end

# app/controllers/application_controller.rb (addition)
class ApplicationController < ActionController::Base
  before_action :set_current_attributes

  private

  # @return [void]
  def set_current_attributes
    Current.user = current_user
    Current.ip_address = request.remote_ip
    Current.request_id = request.request_id
  end
end
```

#### Example 8: API Key Usage Not Tracked for Abuse Detection

**Source:** https://owasp.org/www-project-api-security/ (API4:2023 Unrestricted Resource Consumption)
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/sightings_controller.rb
module Api
  module V1
    class SightingsController < BaseController
      def index
        @sightings = policy_scope(Sighting).includes(:shape, :user)
        # No tracking of API usage — cannot detect abuse patterns,
        # quota violations, or suspicious query patterns
        render json: @sightings
      end
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/base_controller.rb
module Api
  module V1
    class BaseController < ApplicationController
      skip_forgery_protection
      before_action :authenticate_api_key!
      before_action :track_api_usage
      before_action :enforce_rate_limit

      private

      # @return [void]
      def authenticate_api_key!
        key = request.headers["X-Api-Key"]
        return render_unauthorized if key.blank?

        digest = Digest::SHA256.hexdigest(key)
        @api_key = ApiKey.find_by(key_digest: digest, active: true)
        return render_unauthorized unless @api_key

        Rails.logger.info(
          event: "api.request",
          api_key_id: @api_key.id,
          client_name: @api_key.client_name,
          endpoint: "#{request.method} #{request.path}",
          ip: request.remote_ip
        )
      end

      # Track API usage for quota enforcement and abuse detection.
      #
      # @return [void]
      def track_api_usage
        @api_key.increment!(:monthly_request_count)

        if @api_key.monthly_request_count > @api_key.monthly_quota
          Rails.logger.warn(
            event: "api.quota_exceeded",
            api_key_id: @api_key.id,
            client_name: @api_key.client_name,
            quota: @api_key.monthly_quota,
            current_count: @api_key.monthly_request_count
          )
        end
      end

      # @return [void]
      def enforce_rate_limit
        cache_key = "api_rate:#{@api_key.id}:#{Time.current.beginning_of_minute.to_i}"
        count = Rails.cache.increment(cache_key, 1, expires_in: 1.minute, initial: 0)

        return unless count > 60 # 60 requests per minute

        Rails.logger.warn(
          event: "api.rate_limited",
          api_key_id: @api_key.id,
          client_name: @api_key.client_name,
          requests_this_minute: count,
          ip: request.remote_ip
        )

        render json: { error: "Rate limit exceeded" }, status: :too_many_requests
      end

      # @return [void]
      def render_unauthorized
        Rails.logger.warn(
          event: "api.authentication_failed",
          ip: request.remote_ip,
          user_agent: request.user_agent
        )
        render json: { error: "Unauthorized" }, status: :unauthorized
      end
    end
  end
end
```

#### Example 9: Stripe Webhook Events Not Logged for Idempotency Auditing

**Source:** https://stripe.com/docs/webhooks/best-practices
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
module Webhooks
  class StripeController < ApplicationController
    skip_forgery_protection

    def create
      payload = request.body.read
      sig_header = request.headers["Stripe-Signature"]

      event = Stripe::Webhook.construct_event(
        payload, sig_header, Rails.application.credentials.stripe[:webhook_secret]
      )

      case event.type
      when "customer.subscription.updated"
        # Process subscription change but no logging of the event
        # Cannot detect replayed webhooks or processing failures
        handle_subscription_update(event.data.object)
      end

      head :ok
    rescue Stripe::SignatureVerificationError
      # Signature failure not logged — cannot detect webhook forgery attempts
      head :bad_request
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
module Webhooks
  class StripeController < ApplicationController
    skip_forgery_protection

    # Process incoming Stripe webhook events with full audit trail.
    #
    # @return [void]
    def create
      payload = request.body.read
      sig_header = request.headers["Stripe-Signature"]

      event = Stripe::Webhook.construct_event(
        payload, sig_header, Rails.application.credentials.stripe[:webhook_secret]
      )

      # Idempotency: check if we have already processed this event
      if StripeWebhookEvent.exists?(stripe_event_id: event.id)
        Rails.logger.info(
          event: "stripe.webhook.duplicate",
          stripe_event_id: event.id,
          event_type: event.type
        )
        return head(:ok)
      end

      # Record the event BEFORE processing for crash recovery auditing
      webhook_record = StripeWebhookEvent.create!(
        stripe_event_id: event.id,
        event_type: event.type,
        status: "processing",
        received_at: Time.current
      )

      Rails.logger.info(
        event: "stripe.webhook.received",
        stripe_event_id: event.id,
        event_type: event.type,
        webhook_record_id: webhook_record.id
      )

      process_event(event, webhook_record)

      webhook_record.update!(status: "processed", processed_at: Time.current)

      Rails.logger.info(
        event: "stripe.webhook.processed",
        stripe_event_id: event.id,
        event_type: event.type
      )

      head :ok
    rescue Stripe::SignatureVerificationError => e
      Rails.logger.error(
        event: "stripe.webhook.signature_invalid",
        ip: request.remote_ip,
        error: e.message
      )

      AuditLog.create!(
        action: "stripe_webhook_signature_failure",
        metadata: { ip: request.remote_ip }
      )

      head :bad_request
    rescue StandardError => e
      webhook_record&.update!(status: "failed", error_message: e.message)

      Rails.logger.error(
        event: "stripe.webhook.processing_error",
        stripe_event_id: event&.id,
        error_class: e.class.name,
        error_message: e.message
      )

      head :internal_server_error
    end

    private

    # @param event [Stripe::Event] the verified Stripe event
    # @param webhook_record [StripeWebhookEvent] the persistence record
    # @return [void]
    def process_event(event, webhook_record)
      case event.type
      when "customer.subscription.updated", "customer.subscription.deleted"
        ProcessStripeSubscriptionJob.perform_later(
          stripe_event_id: event.id,
          webhook_record_id: webhook_record.id
        )
      when "invoice.payment_failed"
        ProcessStripePaymentFailureJob.perform_later(
          stripe_event_id: event.id,
          webhook_record_id: webhook_record.id
        )
      else
        Rails.logger.info(
          event: "stripe.webhook.unhandled_type",
          stripe_event_id: event.id,
          event_type: event.type
        )
      end
    end
  end
end
```

#### Example 10: No Alerting on Brute-Force or Privilege Escalation Patterns

**Source:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Brute_Force
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# No mechanism to detect or alert on:
# - Multiple failed logins from the same IP
# - Sudden privilege escalation (member -> admin)
# - Bulk data export via API
# - Geographic anomalies in login locations
#
# The application logs events but nobody is watching.
# Without automated alerting, logged events are forensic-only.
```

**Secure Fix:**
```ruby
# app/jobs/security_alert_job.rb
# Background job that evaluates security events and triggers alerts
# when thresholds are exceeded. Runs via Solid Queue.
class SecurityAlertJob < ApplicationJob
  queue_as :security

  FAILED_LOGIN_THRESHOLD = 10
  FAILED_LOGIN_WINDOW = 15.minutes
  API_ABUSE_THRESHOLD = 1000
  API_ABUSE_WINDOW = 1.hour

  # Evaluate recent security events and trigger alerts.
  #
  # @param check_type [String] the type of security check to perform
  # @return [void]
  def perform(check_type)
    case check_type
    when "brute_force"
      detect_brute_force
    when "privilege_escalation"
      detect_privilege_escalation
    when "api_abuse"
      detect_api_abuse
    end
  end

  private

  # @return [void]
  def detect_brute_force
    # Group failed logins by IP in the recent window
    suspicious_ips = AuditLog
      .where(action: "login_failure")
      .where(created_at: FAILED_LOGIN_WINDOW.ago..)
      .group("metadata->>'ip'")
      .having("COUNT(*) >= ?", FAILED_LOGIN_THRESHOLD)
      .count

    suspicious_ips.each do |ip, count|
      Rails.logger.error(
        event: "security.alert.brute_force_detected",
        ip: ip,
        failed_attempts: count,
        window_minutes: FAILED_LOGIN_WINDOW / 60,
        severity: "high"
      )

      SecurityMailer.brute_force_alert(ip: ip, count: count).deliver_later
    end
  end

  # @return [void]
  def detect_privilege_escalation
    recent_escalations = AuditLog
      .where(action: "user.updated")
      .where(created_at: 1.hour.ago..)
      .select { |log| log.metadata.dig("changes", "role").present? }

    recent_escalations.each do |log|
      old_role, new_role = log.metadata.dig("changes", "role")

      Rails.logger.error(
        event: "security.alert.privilege_escalation",
        user_id: log.resource_id,
        changed_by: log.user_id,
        old_role: old_role,
        new_role: new_role,
        severity: "critical"
      )

      SecurityMailer.privilege_escalation_alert(
        user_id: log.resource_id,
        old_role: old_role,
        new_role: new_role,
        changed_by: log.user_id
      ).deliver_later
    end
  end

  # @return [void]
  def detect_api_abuse
    abusive_keys = ApiKey
      .where("monthly_request_count > monthly_quota * 2")
      .where(active: true)

    abusive_keys.each do |api_key|
      Rails.logger.error(
        event: "security.alert.api_abuse",
        api_key_id: api_key.id,
        client_name: api_key.client_name,
        request_count: api_key.monthly_request_count,
        quota: api_key.monthly_quota,
        severity: "high"
      )
    end
  end
end

# config/initializers/security_alert_schedule.rb
# Schedule periodic security checks via Solid Queue recurring tasks.
# These run in addition to real-time logging and provide aggregate analysis.
Rails.application.config.after_initialize do
  if defined?(SolidQueue) && Rails.env.production?
    # Schedule is defined in config/recurring.yml for Solid Queue
    Rails.logger.info(event: "security.alert_schedule.initialized")
  end
end

# config/recurring.yml
# brute_force_check:
#   class: SecurityAlertJob
#   args: ["brute_force"]
#   schedule: every 5 minutes
# privilege_escalation_check:
#   class: SecurityAlertJob
#   args: ["privilege_escalation"]
#   schedule: every 15 minutes
# api_abuse_check:
#   class: SecurityAlertJob
#   args: ["api_abuse"]
#   schedule: every 1 hour
```

## Checklist

- [ ] `config.filter_parameters` includes ALL sensitive fields: password, token, key, secret, stripe, email, phone, address, latitude, longitude, coordinates, card, api_key, api_key_digest
- [ ] All log statements use structured hash format (`event: "name", key: value`) instead of string interpolation
- [ ] No user-supplied text is interpolated into log messages; use separate structured fields
- [ ] Production logging uses JSON formatter compatible with log aggregation tools (Lograge or custom JSON formatter)
- [ ] Production log level is `:info` or above (no `:debug` query logging in production)
- [ ] `AuditLog` entries are created for: login success/failure, logout, authorization denial, record create/update/destroy, role changes, API key creation/revocation
- [ ] Warden hooks log all authentication events (success, failure, logout) with IP and request metadata
- [ ] Stripe webhook events are persisted to `StripeWebhookEvent` with status tracking before processing begins
- [ ] Stripe signature verification failures are logged with source IP
- [ ] `Auditable` concern (or equivalent) is included on all security-sensitive models: `Sighting`, `User`, `Investigation`, `Evidence`, `Membership`, `Witness`
- [ ] API key usage is tracked per request with endpoint, IP, and timestamp
- [ ] API rate limiting logs violations with key ID and request count
- [ ] `Current` attributes (user, IP, request_id) are set in `ApplicationController` for audit context
- [ ] Security alerting job runs on recurring schedule checking: brute force, privilege escalation, API abuse
- [ ] No PII (email, phone, name, address) appears in any log output — verify with `grep -rn` in log files
- [ ] SQL query logging is suppressed or filtered in production to prevent credential/PII leakage in query parameters
