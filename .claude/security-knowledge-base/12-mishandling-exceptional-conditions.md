# A12 — Mishandling Exceptional Conditions

## Overview

Mishandling Exceptional Conditions (OWASP 2025 A10) occurs when an application fails to properly anticipate, detect, and handle error states. This includes swallowing exceptions silently, rescuing overly broad exception classes, leaking sensitive information through error messages, failing to maintain data consistency when partial operations fail, and missing retry logic for transient failures. These failures can lead to data corruption, security bypasses, denial of service, information disclosure, and systems that silently operate in a degraded or compromised state.

For the APRS platform, this risk is pervasive across the entire architecture. The system integrates with 13 external enrichment and deconfliction APIs, each with varying reliability, rate limits, and failure modes. Stripe webhook processing requires precise error handling to prevent duplicate charges, missed subscription updates, or race conditions between concurrent webhook deliveries. PostGIS spatial queries can fail due to invalid geometries, coordinate range violations, or database connection exhaustion. Active Storage uploads to DigitalOcean Spaces can fail mid-transfer. Solid Queue background jobs need proper retry strategies with exponential backoff to avoid thundering herd problems.

The deconfliction pipeline is particularly vulnerable because it orchestrates multiple API calls that may partially succeed. If three of five API calls succeed and the fourth fails, the system must decide whether to save partial results, retry the failed call, or roll back the entire operation. Without explicit handling, partial results may be silently committed as complete, misleading investigators who rely on the data for their analysis. Similarly, Stripe webhook processing faces TOCTOU (time-of-check-to-time-of-use) race conditions when multiple webhooks for the same subscription arrive concurrently, and improper exception handling during these race conditions can leave `Membership` records in an inconsistent state.

## APRS-Specific Attack Surface

- **External API failures**: 13 enrichment/deconfliction APIs with varying reliability, each requiring specific error handling for timeouts, rate limits, authentication failures, and malformed responses
- **Stripe webhook processing errors**: Signature verification failures, duplicate event delivery, subscription state race conditions, and payment processing errors
- **PostGIS query failures**: Invalid geometries, out-of-range coordinates (SRID 4326 bounds), connection pool exhaustion, and spatial index corruption
- **Active Storage upload failures**: Network interruptions during upload to DigitalOcean Spaces, content-type validation errors, file size limit violations
- **Solid Queue job failures and retries**: Background job crashes, retry storms, poison pill messages, and dead letter handling
- **Database connection issues**: Pool exhaustion, connection timeouts, and failover during transactions
- **Rate limit exceeded handling**: Both inbound (API consumers) and outbound (enrichment APIs) rate limiting
- **Malformed sighting data**: Invalid coordinates, impossible timestamps, missing required enrichment fields
- **Deconfliction pipeline partial failures**: Some APIs succeed while others fail, requiring partial result handling
- **Concurrent webhook race conditions**: Multiple Stripe events for the same subscription arriving simultaneously

## Examples

### Basic Level

#### Example 1: Swallowing Exceptions Silently

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/sighting_enrichment_service.rb
class SightingEnrichmentService
  def enrich(sighting)
    weather = fetch_weather(sighting)
    sighting.update(weather_conditions: weather)
  rescue StandardError
    # Silently swallowed — no logging, no error tracking, no indication
    # that enrichment failed. The sighting appears "enriched" but has
    # no weather data. Investigators may assume clear skies when in
    # reality the API call simply failed.
    nil
  end

  private

  def fetch_weather(sighting)
    # API call that could fail for many reasons
    WeatherApi.fetch(lat: sighting.latitude, lon: sighting.longitude)
  end
end
```

**Secure Fix:**
```ruby
# app/services/sighting_enrichment_service.rb
class SightingEnrichmentService
  # Enrich a sighting with weather data from external API.
  # Records the enrichment status regardless of outcome.
  #
  # @param sighting [Sighting] the sighting to enrich
  # @return [WeatherCondition, nil] the created weather record or nil on failure
  def enrich(sighting)
    weather_data = fetch_weather(sighting)

    weather_condition = WeatherCondition.create!(
      sighting: sighting,
      status: "success",
      temperature: weather_data[:temperature],
      cloud_cover: weather_data[:cloud_cover],
      visibility: weather_data[:visibility],
      wind_speed: weather_data[:wind_speed],
      source: "weather_gov",
      fetched_at: Time.current
    )

    Rails.logger.info(
      event: "enrichment.weather.success",
      sighting_id: sighting.id,
      source: "weather_gov"
    )

    weather_condition
  rescue Net::OpenTimeout, Net::ReadTimeout => e
    record_enrichment_failure(sighting, "timeout", e)
  rescue Net::HTTPError => e
    record_enrichment_failure(sighting, "http_error", e)
  rescue JSON::ParserError => e
    record_enrichment_failure(sighting, "invalid_response", e)
  rescue StandardError => e
    record_enrichment_failure(sighting, "unexpected_error", e)
    # Re-raise unexpected errors so they reach error tracking (Sentry, etc.)
    raise
  end

  private

  # Record an enrichment failure with full context.
  #
  # @param sighting [Sighting] the sighting
  # @param reason [String] the failure category
  # @param error [StandardError] the caught exception
  # @return [WeatherCondition]
  def record_enrichment_failure(sighting, reason, error)
    Rails.logger.error(
      event: "enrichment.weather.failed",
      sighting_id: sighting.id,
      reason: reason,
      error_class: error.class.name,
      error_message: error.message
    )

    WeatherCondition.create!(
      sighting: sighting,
      status: "failed",
      failure_reason: reason,
      fetched_at: Time.current
    )
  end
end
```

#### Example 2: Rescuing StandardError/Exception Too Broadly

**Source:** https://www.exceptionalcreatures.com/bestiary/StandardError (Ruby exception hierarchy documentation)
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/sightings_controller.rb
module Api
  module V1
    class SightingsController < BaseController
      def create
        @sighting = current_api_user.sightings.build(sighting_params)
        authorize @sighting

        @sighting.save!
        EnrichSightingJob.perform_later(@sighting.id)
        render json: @sighting, status: :created
      rescue Exception => e
        # CRITICAL: Rescuing Exception catches:
        # - SignalException (SIGTERM, SIGINT) — prevents graceful shutdown
        # - NoMemoryError — hides OOM conditions
        # - SystemStackError — hides infinite recursion
        # - Pundit::NotAuthorizedError — SILENCES authorization failures!
        # - LoadError, SyntaxError — hides code loading issues
        render json: { error: e.message }, status: :internal_server_error
      end
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/sightings_controller.rb
module Api
  module V1
    class SightingsController < BaseController
      # Create a new sighting via API.
      #
      # @return [void]
      # @raise [Pundit::NotAuthorizedError] if API key lacks permission
      def create
        @sighting = current_api_user.sightings.build(sighting_params)
        authorize @sighting

        @sighting.save!
        EnrichSightingJob.perform_later(@sighting.id)

        Rails.logger.info(
          event: "api.sighting.created",
          sighting_id: @sighting.id,
          api_key_id: @api_key.id
        )

        render json: @sighting, status: :created
      rescue ActiveRecord::RecordInvalid => e
        # Validation errors — client's fault, return details
        render json: { errors: e.record.errors.full_messages },
               status: :unprocessable_entity
      rescue ActiveRecord::RecordNotFound => e
        render json: { error: "Resource not found" }, status: :not_found
      end
      # Let Pundit::NotAuthorizedError propagate to ApplicationController handler
      # Let SignalException, NoMemoryError, etc. propagate to the runtime
      # Let unexpected StandardError propagate to error tracking middleware
    end
  end
end

# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  include Pundit::Authorization

  # Handle Pundit separately so it is NEVER swallowed
  rescue_from Pundit::NotAuthorizedError, with: :handle_unauthorized

  # Handle only application-level errors in the catch-all
  rescue_from StandardError, with: :handle_unexpected_error

  private

  # @param exception [StandardError]
  # @return [void]
  def handle_unexpected_error(exception)
    # Log with full context for debugging
    Rails.logger.error(
      event: "unhandled_error",
      error_class: exception.class.name,
      error_message: exception.message,
      backtrace: exception.backtrace&.first(10),
      path: request.fullpath,
      user_id: current_user&.id
    )

    if request.format.json?
      # Never expose internal error details to API consumers
      render json: { error: "Internal server error" },
             status: :internal_server_error
    else
      render "errors/internal_server_error",
             status: :internal_server_error
    end
  end
end
```

#### Example 3: Information Disclosure via Error Messages

**Source:** https://owasp.org/www-community/Improper_Error_Handling
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/sightings_controller.rb
class SightingsController < ApplicationController
  def show
    @sighting = Sighting.find(params[:id])
    authorize @sighting
  rescue ActiveRecord::RecordNotFound => e
    # Leaks table name, column name, and query structure
    flash[:alert] = "Error: #{e.message}"
    redirect_to sightings_path
  rescue Pundit::NotAuthorizedError => e
    # Leaks policy class name and internal authorization logic
    flash[:alert] = "Authorization failed: #{e.policy.class}##{e.query} " \
                    "for #{e.record.class}##{e.record.id}"
    redirect_to root_path
  end

  def search
    @sightings = Sighting.where(
      "ST_DWithin(location, ST_MakePoint(:lon, :lat)::geography, :radius)",
      lat: params[:lat], lon: params[:lon], radius: params[:radius]
    )
    authorize @sightings
  rescue ActiveRecord::StatementInvalid => e
    # Leaks full SQL query, PostGIS function names, and database structure
    render json: { error: e.message }, status: :bad_request
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/sightings_controller.rb
class SightingsController < ApplicationController
  # @return [void]
  def show
    @sighting = Sighting.find(params[:id])
    authorize @sighting
  rescue ActiveRecord::RecordNotFound
    # Generic message — never reveal table/column structure
    flash[:alert] = "The requested sighting could not be found."
    redirect_to sightings_path
  end
  # Pundit::NotAuthorizedError handled by ApplicationController

  # @return [void]
  def search
    @sightings = policy_scope(Sighting).nearby(
      latitude: validated_lat,
      longitude: validated_lon,
      radius: validated_radius
    )
  rescue ArgumentError => e
    # Only show validation errors, not database errors
    flash[:alert] = "Invalid search parameters. Please check your coordinates and radius."
    redirect_to sightings_path
  rescue ActiveRecord::StatementInvalid => e
    # Log full details internally, show generic message to user
    Rails.logger.error(
      event: "sighting.search.query_error",
      error_class: e.class.name,
      error_message: e.message,
      user_id: current_user&.id,
      params: { lat: params[:lat], lon: params[:lon], radius: params[:radius] }
    )
    flash[:alert] = "Search could not be completed. Please try again."
    redirect_to sightings_path
  end

  private

  # @return [Float] validated latitude
  # @raise [ArgumentError] if latitude is out of range
  def validated_lat
    lat = Float(params[:lat])
    raise ArgumentError, "Latitude out of range" unless lat.between?(-90, 90)

    lat
  end

  # @return [Float] validated longitude
  # @raise [ArgumentError] if longitude is out of range
  def validated_lon
    lon = Float(params[:lon])
    raise ArgumentError, "Longitude out of range" unless lon.between?(-180, 180)

    lon
  end

  # @return [Float] validated search radius in meters
  # @raise [ArgumentError] if radius is invalid
  def validated_radius
    radius = Float(params[:radius])
    raise ArgumentError, "Radius must be positive" unless radius.positive?
    raise ArgumentError, "Radius too large" if radius > 500_000 # 500km max

    radius
  end
end
```

### Intermediate Level

#### Example 4: Missing Error Handling in Background Jobs

**Source:** https://edgeapi.rubyonrails.org/classes/ActiveJob/Exceptions/ClassMethods.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/jobs/enrich_sighting_job.rb
class EnrichSightingJob < ApplicationJob
  queue_as :enrichment

  def perform(sighting_id)
    sighting = Sighting.find(sighting_id)

    # No error handling — if any enrichment fails:
    # 1. Solid Queue retries immediately (default), causing thundering herd
    # 2. Transient API failures trigger permanent job failure after retries
    # 3. No distinction between retryable and permanent failures
    # 4. No dead letter handling for poison pill messages
    WeatherEnrichmentService.new.enrich(sighting)
    AircraftDeconflictionService.new.check_aircraft(sighting)
    SatelliteEnrichmentService.new.fetch_imagery(sighting)
    NotamService.new.check_notams(sighting)

    sighting.update!(enrichment_status: "complete")
  end
end
```

**Secure Fix:**
```ruby
# app/jobs/enrich_sighting_job.rb
class EnrichSightingJob < ApplicationJob
  queue_as :enrichment

  # Retry transient failures with exponential backoff.
  # Net timeouts and HTTP 5xx are retryable; validation errors are not.
  retry_on Net::OpenTimeout,
           Net::ReadTimeout,
           Faraday::ConnectionFailed,
           wait: :polynomially_longer,
           attempts: 5

  # Do NOT retry permanent failures — these need human investigation
  discard_on ActiveRecord::RecordNotFound
  discard_on ActiveRecord::RecordInvalid

  # Catch-all for unexpected errors after all retries exhausted
  retry_on StandardError, wait: :polynomially_longer, attempts: 3 do |job, error|
    handle_permanent_failure(job, error)
  end

  # Run the enrichment pipeline for a sighting.
  #
  # @param sighting_id [Integer] the sighting ID to enrich
  # @return [void]
  def perform(sighting_id)
    sighting = Sighting.find(sighting_id)
    sighting.update!(enrichment_status: "in_progress")

    results = {}

    results[:weather] = run_enrichment("weather", sighting) do
      WeatherEnrichmentService.new.enrich(sighting)
    end

    results[:aircraft] = run_enrichment("aircraft", sighting) do
      AircraftDeconflictionService.new.check_aircraft(sighting)
    end

    results[:satellite] = run_enrichment("satellite", sighting) do
      SatelliteEnrichmentService.new.fetch_imagery(sighting)
    end

    results[:notam] = run_enrichment("notam", sighting) do
      NotamService.new.check_notams(sighting)
    end

    # Determine overall status from individual results
    final_status = if results.values.all? { |r| r == :success }
                     "complete"
                   elsif results.values.any? { |r| r == :success }
                     "partial"
                   else
                     "failed"
                   end

    sighting.update!(
      enrichment_status: final_status,
      enriched_at: Time.current
    )

    Rails.logger.info(
      event: "enrichment.pipeline.completed",
      sighting_id: sighting.id,
      status: final_status,
      results: results
    )
  end

  private

  # Run a single enrichment step with isolated error handling.
  # One step failing does not prevent others from running.
  #
  # @param source [String] the enrichment source name
  # @param sighting [Sighting] the sighting being enriched
  # @yield the enrichment block to execute
  # @return [Symbol] :success or :failed
  def run_enrichment(source, sighting)
    yield
    :success
  rescue Net::OpenTimeout, Net::ReadTimeout => e
    Rails.logger.warn(
      event: "enrichment.step.timeout",
      source: source,
      sighting_id: sighting.id,
      error: e.message
    )
    :failed
  rescue StandardError => e
    Rails.logger.error(
      event: "enrichment.step.error",
      source: source,
      sighting_id: sighting.id,
      error_class: e.class.name,
      error_message: e.message
    )
    :failed
  end

  # Handle a job that has permanently failed after all retries.
  #
  # @param job [EnrichSightingJob] the failed job
  # @param error [StandardError] the final error
  # @return [void]
  def self.handle_permanent_failure(job, error)
    sighting_id = job.arguments.first

    Rails.logger.error(
      event: "enrichment.pipeline.permanent_failure",
      sighting_id: sighting_id,
      error_class: error.class.name,
      error_message: error.message,
      job_id: job.job_id,
      executions: job.executions
    )

    Sighting.where(id: sighting_id).update_all(
      enrichment_status: "permanently_failed",
      updated_at: Time.current
    )

    # Notify admins of permanent failure for investigation
    AdminMailer.enrichment_permanent_failure(
      sighting_id: sighting_id,
      error_class: error.class.name,
      error_message: error.message
    ).deliver_later
  end
end
```

#### Example 5: Race Conditions in Stripe Webhook Processing (TOCTOU)

**Source:** https://stripe.com/docs/webhooks/best-practices#handle-duplicate-events
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/jobs/process_stripe_subscription_job.rb
class ProcessStripeSubscriptionJob < ApplicationJob
  queue_as :webhooks

  def perform(stripe_event_id:, webhook_record_id:)
    event = Stripe::Event.retrieve(stripe_event_id)
    subscription = event.data.object

    # TOCTOU race condition: Two webhooks for the same subscription
    # arrive milliseconds apart (e.g., customer.subscription.updated
    # followed by customer.subscription.deleted).
    #
    # Both jobs read the membership, both see status="active",
    # both try to update. Without locking:
    # - Job A sets tier to "premium"
    # - Job B sets status to "canceled"
    # - Final state depends on execution order — could end up with
    #   a "premium" tier on a "canceled" membership
    membership = Membership.find_by!(stripe_subscription_id: subscription.id)
    membership.update!(
      tier: map_tier(subscription),
      status: subscription.status,
      current_period_end: Time.at(subscription.current_period_end).utc
    )
  end
end
```

**Secure Fix:**
```ruby
# app/jobs/process_stripe_subscription_job.rb
class ProcessStripeSubscriptionJob < ApplicationJob
  queue_as :webhooks

  retry_on ActiveRecord::Deadlocked, wait: :polynomially_longer, attempts: 3
  retry_on Stripe::APIConnectionError, wait: :polynomially_longer, attempts: 5

  # Process a Stripe subscription webhook event.
  # Uses pessimistic locking to prevent TOCTOU race conditions
  # when multiple webhooks for the same subscription arrive concurrently.
  #
  # @param stripe_event_id [String] the Stripe event ID
  # @param webhook_record_id [Integer] the local webhook record ID
  # @return [void]
  def perform(stripe_event_id:, webhook_record_id:)
    webhook_record = StripeWebhookEvent.find(webhook_record_id)

    # Idempotency check before processing
    return if webhook_record.status == "processed"

    # ALWAYS re-fetch from Stripe API — never trust webhook payload
    event = Stripe::Event.retrieve(stripe_event_id)
    subscription = Stripe::Subscription.retrieve(event.data.object.id)

    # Use a database transaction with pessimistic locking
    # to prevent concurrent updates to the same membership
    ActiveRecord::Base.transaction do
      membership = Membership
        .lock("FOR UPDATE NOWAIT")
        .find_by!(stripe_subscription_id: subscription.id)

      # Only apply the update if this event is newer than the last processed
      if webhook_record.received_at <= membership.last_webhook_at.to_i
        Rails.logger.info(
          event: "stripe.webhook.stale_event",
          stripe_event_id: stripe_event_id,
          membership_id: membership.id,
          event_time: webhook_record.received_at,
          last_processed: membership.last_webhook_at
        )
        webhook_record.update!(status: "skipped_stale")
        return
      end

      membership.update!(
        tier: map_tier(subscription),
        status: map_status(subscription.status),
        current_period_end: Time.at(subscription.current_period_end).utc,
        last_webhook_at: webhook_record.received_at
      )

      webhook_record.update!(status: "processed", processed_at: Time.current)

      Rails.logger.info(
        event: "stripe.subscription.updated",
        membership_id: membership.id,
        user_id: membership.user_id,
        tier: membership.tier,
        status: membership.status,
        stripe_event_id: stripe_event_id
      )
    end
  rescue ActiveRecord::LockWaitTimeout
    # Another job holds the lock — retry with backoff
    Rails.logger.warn(
      event: "stripe.webhook.lock_contention",
      stripe_event_id: stripe_event_id,
      webhook_record_id: webhook_record_id
    )
    raise # Will trigger retry_on ActiveRecord::Deadlocked
  rescue ActiveRecord::RecordNotFound => e
    Rails.logger.error(
      event: "stripe.webhook.membership_not_found",
      stripe_event_id: stripe_event_id,
      error: e.message
    )
    webhook_record&.update!(status: "failed", error_message: "Membership not found")
  end

  private

  # Map Stripe plan to APRS tier name.
  #
  # @param subscription [Stripe::Subscription] the Stripe subscription
  # @return [String] the APRS tier name
  def map_tier(subscription)
    plan_id = subscription.items.data.first.price.id
    case plan_id
    when Rails.application.credentials.dig(:stripe, :basic_price_id) then "basic"
    when Rails.application.credentials.dig(:stripe, :premium_price_id) then "premium"
    when Rails.application.credentials.dig(:stripe, :platinum_price_id) then "platinum"
    else
      Rails.logger.warn(
        event: "stripe.webhook.unknown_plan",
        plan_id: plan_id
      )
      "basic"
    end
  end

  # Map Stripe subscription status to APRS membership status.
  #
  # @param stripe_status [String] the Stripe status
  # @return [String] the APRS status
  def map_status(stripe_status)
    case stripe_status
    when "active", "trialing" then "active"
    when "past_due" then "past_due"
    when "canceled", "unpaid" then "canceled"
    when "incomplete", "incomplete_expired" then "incomplete"
    else "unknown"
    end
  end
end
```

#### Example 6: Unhandled Nil in Deconfliction Results

**Source:** https://ruby-doc.org/core/NilClass.html (NoMethodError on nil)
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/deconfliction_summary_service.rb
class DeconflictionSummaryService
  def summarize(sighting)
    results = sighting.deconfliction_results

    # If any API returned no aircraft, .first returns nil
    # Calling .distance on nil raises NoMethodError
    closest_aircraft = results
      .find_by(source: "aircraft")
      .parsed_data["aircraft"]
      .sort_by { |a| a["distance"] }
      .first

    # NoMethodError: undefined method `[]' for nil:NilClass
    summary = {
      closest_aircraft_distance: closest_aircraft["distance"],
      closest_aircraft_callsign: closest_aircraft["callsign"],
      weather_visibility: results.find_by(source: "weather")
                                  .parsed_data["visibility"],
      notam_active: results.find_by(source: "notam")
                            .parsed_data["notams"]
                            .any? { |n| n["active"] }
    }

    sighting.update!(deconfliction_summary: summary)
  end
end
```

**Secure Fix:**
```ruby
# app/services/deconfliction_summary_service.rb
class DeconflictionSummaryService
  # Build a deconfliction summary from all available results.
  # Handles missing or failed enrichment sources gracefully.
  #
  # @param sighting [Sighting] the sighting to summarize
  # @return [Hash] the summary data
  def summarize(sighting)
    results = sighting.deconfliction_results.index_by(&:source)

    summary = {
      closest_aircraft: extract_closest_aircraft(results["aircraft"]),
      weather: extract_weather(results["weather"]),
      notam: extract_notam(results["notam"]),
      sources_available: results.keys,
      sources_failed: detect_failed_sources(results),
      generated_at: Time.current.iso8601
    }

    sighting.update!(deconfliction_summary: summary)

    Rails.logger.info(
      event: "deconfliction.summary.generated",
      sighting_id: sighting.id,
      sources_available: summary[:sources_available],
      sources_failed: summary[:sources_failed]
    )

    summary
  end

  private

  # Extract closest aircraft data, handling missing or empty results.
  #
  # @param result [DeconflictionResult, nil] the aircraft deconfliction result
  # @return [Hash] aircraft data with distance and callsign, or unavailable marker
  def extract_closest_aircraft(result)
    return { status: "unavailable", reason: "no_data" } if result.nil?
    return { status: "failed", reason: result.failure_reason } if result.status == "failed"

    aircraft_list = result.parsed_data&.dig("aircraft")
    return { status: "none_detected" } if aircraft_list.blank?

    closest = aircraft_list.min_by { |a| a["distance"].to_f }
    return { status: "none_detected" } if closest.nil?

    {
      status: "detected",
      distance_meters: closest["distance"]&.to_f,
      callsign: closest["callsign"],
      altitude_meters: closest["altitude"]&.to_f,
      heading: closest["heading"]&.to_f
    }
  end

  # Extract weather data, handling missing or failed results.
  #
  # @param result [DeconflictionResult, nil] the weather result
  # @return [Hash] weather data or unavailable marker
  def extract_weather(result)
    return { status: "unavailable", reason: "no_data" } if result.nil?
    return { status: "failed", reason: result.failure_reason } if result.status == "failed"

    parsed = result.parsed_data
    return { status: "unavailable", reason: "empty_response" } if parsed.blank?

    {
      status: "available",
      visibility_meters: parsed.dig("visibility")&.to_f,
      cloud_cover_percent: parsed.dig("cloud_cover")&.to_f,
      temperature_celsius: parsed.dig("temperature")&.to_f
    }
  end

  # Extract NOTAM data, handling missing or failed results.
  #
  # @param result [DeconflictionResult, nil] the NOTAM result
  # @return [Hash] NOTAM data or unavailable marker
  def extract_notam(result)
    return { status: "unavailable", reason: "no_data" } if result.nil?
    return { status: "failed", reason: result.failure_reason } if result.status == "failed"

    notams = result.parsed_data&.dig("notams")
    return { status: "none_active" } if notams.blank?

    active_notams = notams.select { |n| n["active"] == true }

    {
      status: active_notams.any? ? "active_notams_present" : "none_active",
      active_count: active_notams.size,
      total_count: notams.size
    }
  end

  # Identify which enrichment sources failed.
  #
  # @param results [Hash<String, DeconflictionResult>] indexed results
  # @return [Array<String>] names of failed sources
  def detect_failed_sources(results)
    expected_sources = %w[weather aircraft satellite notam]
    failed = expected_sources.select do |source|
      results[source].nil? || results[source].status == "failed"
    end
    failed
  end
end
```

### Advanced Level

#### Example 7: Partial Pipeline Failure Without Rollback

**Source:** https://guides.rubyonrails.org/active_record_transactions.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/investigation_assignment_service.rb
class InvestigationAssignmentService
  def assign(investigation, investigator, sighting_ids)
    # Step 1: Update investigation
    investigation.update!(
      investigator: investigator,
      status: "assigned",
      assigned_at: Time.current
    )

    # Step 2: Link sightings to investigation
    sighting_ids.each do |id|
      sighting = Sighting.find(id)
      sighting.update!(investigation: investigation)
    end

    # Step 3: Notify investigator
    InvestigatorMailer.assignment_notification(
      investigation: investigation,
      investigator: investigator
    ).deliver_later

    # Step 4: Create timeline entry
    investigation.timeline_entries.create!(
      event_type: "assigned",
      user: Current.user,
      details: "Assigned to #{investigator.email}"
    )

    # PROBLEM: If Step 2 fails on the 3rd sighting (e.g., RecordNotFound),
    # the investigation is already marked "assigned" with 2 of 5 sightings
    # linked. The data is in an inconsistent state. The notification may
    # have already been queued. No rollback occurs.
  end
end
```

**Secure Fix:**
```ruby
# app/services/investigation_assignment_service.rb
class InvestigationAssignmentService
  # Assign an investigation to an investigator with transactional consistency.
  # All database operations succeed together or fail together.
  # Side effects (email, jobs) are deferred until after commit.
  #
  # @param investigation [Investigation] the investigation to assign
  # @param investigator [User] the user receiving the assignment
  # @param sighting_ids [Array<Integer>] IDs of sightings to include
  # @return [Investigation] the updated investigation
  # @raise [AssignmentError] if assignment cannot be completed
  def assign(investigation, investigator, sighting_ids)
    validate_assignment!(investigation, investigator, sighting_ids)

    ActiveRecord::Base.transaction do
      # Lock the investigation to prevent concurrent assignments
      investigation.lock!

      # Verify state has not changed since validation
      unless investigation.status.in?(%w[new unassigned])
        raise AssignmentError, "Investigation is already #{investigation.status}"
      end

      investigation.update!(
        investigator: investigator,
        status: "assigned",
        assigned_at: Time.current
      )

      # Load all sightings at once to fail fast if any are missing
      sightings = Sighting.where(id: sighting_ids).lock("FOR UPDATE")
      missing_ids = sighting_ids - sightings.map(&:id)
      if missing_ids.any?
        raise AssignmentError, "Sightings not found: #{missing_ids.join(', ')}"
      end

      # Verify no sighting is already assigned to another investigation
      already_assigned = sightings.select { |s| s.investigation_id.present? && s.investigation_id != investigation.id }
      if already_assigned.any?
        raise AssignmentError,
              "Sightings already assigned: #{already_assigned.map(&:id).join(', ')}"
      end

      sightings.update_all(
        investigation_id: investigation.id,
        updated_at: Time.current
      )

      investigation.timeline_entries.create!(
        event_type: "assigned",
        user: Current.user,
        details: { investigator_id: investigator.id, sighting_count: sightings.size }
      )

      Rails.logger.info(
        event: "investigation.assigned",
        investigation_id: investigation.id,
        investigator_id: investigator.id,
        sighting_count: sightings.size
      )
    end

    # Side effects AFTER successful commit only.
    # If the transaction rolled back, this code never runs.
    InvestigatorMailer.assignment_notification(
      investigation: investigation,
      investigator: investigator
    ).deliver_later

    investigation
  rescue ActiveRecord::RecordInvalid => e
    raise AssignmentError, "Validation failed: #{e.record.errors.full_messages.join(', ')}"
  end

  private

  # Validate assignment preconditions before starting transaction.
  #
  # @param investigation [Investigation]
  # @param investigator [User]
  # @param sighting_ids [Array<Integer>]
  # @return [void]
  # @raise [AssignmentError] if preconditions are not met
  def validate_assignment!(investigation, investigator, sighting_ids)
    raise AssignmentError, "Investigation is required" if investigation.nil?
    raise AssignmentError, "Investigator is required" if investigator.nil?
    raise AssignmentError, "Investigator must have investigator role" unless investigator.investigator? || investigator.admin?
    raise AssignmentError, "At least one sighting is required" if sighting_ids.blank?
    raise AssignmentError, "Too many sightings (max 50)" if sighting_ids.size > 50
  end
end

class AssignmentError < StandardError; end
```

#### Example 8: Missing Retry Logic with Exponential Backoff for External APIs

**Source:** https://docs.aws.amazon.com/general/latest/gr/api-retries.html (exponential backoff best practices)
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/notam_service.rb
class NotamService
  API_URL = "https://api.faa.gov/notam/v1/notams".freeze

  def check_notams(sighting)
    uri = URI("#{API_URL}?lat=#{sighting.latitude}&lon=#{sighting.longitude}")
    response = Net::HTTP.get_response(uri)

    # No retry logic at all. If the FAA API returns:
    # - 429 (rate limited): permanent failure instead of backing off
    # - 503 (maintenance): fails when a retry 30s later would succeed
    # - Timeout: fails when the server was momentarily overloaded
    # - Connection reset: fails for a transient network issue
    raise "API error: #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  end
end
```

**Secure Fix:**
```ruby
# app/services/notam_service.rb
class NotamService
  API_HOST = "api.faa.gov".freeze
  API_URL = "https://#{API_HOST}/notam/v1/notams".freeze

  MAX_RETRIES = 3
  BASE_DELAY = 1.0   # seconds
  MAX_DELAY = 30.0    # seconds

  # HTTP status codes that indicate a retryable failure
  RETRYABLE_STATUS_CODES = [429, 500, 502, 503, 504].freeze

  # Check for active NOTAMs near the sighting location.
  #
  # @param sighting [Sighting] the sighting to check
  # @return [Hash] parsed NOTAM data
  # @raise [NotamServiceError] if all retries are exhausted
  def check_notams(sighting)
    url = "#{API_URL}?lat=#{sighting.latitude}&lon=#{sighting.longitude}" \
          "&radius=25&pageSize=50"

    response = fetch_with_retries(url)
    JSON.parse(response.body)
  rescue JSON::ParserError => e
    Rails.logger.error(
      event: "notam.parse_error",
      sighting_id: sighting.id,
      error: e.message
    )
    raise NotamServiceError, "Invalid response from NOTAM API"
  end

  private

  # Fetch a URL with exponential backoff and jitter.
  #
  # @param url [String] the URL to fetch
  # @return [Net::HTTPResponse] a successful response
  # @raise [NotamServiceError] if all retries fail
  def fetch_with_retries(url)
    validated_uri = UrlValidator.validate!(url, allowed_hosts: [API_HOST])
    last_error = nil

    (0..MAX_RETRIES).each do |attempt|
      response = SafeHttpClient.get_with_pinned_dns(validated_uri, timeout: 15)

      if response.is_a?(Net::HTTPSuccess)
        log_attempt(url, attempt, response.code, "success")
        return response
      end

      if RETRYABLE_STATUS_CODES.include?(response.code.to_i)
        delay = calculate_backoff(attempt, response)
        log_attempt(url, attempt, response.code, "retrying", delay: delay)
        sleep(delay) if attempt < MAX_RETRIES
        last_error = "HTTP #{response.code}"
      else
        # Non-retryable error (4xx client errors except 429)
        log_attempt(url, attempt, response.code, "permanent_failure")
        raise NotamServiceError, "NOTAM API returned #{response.code}"
      end
    end

    Rails.logger.error(
      event: "notam.retries_exhausted",
      url_host: API_HOST,
      last_error: last_error,
      max_retries: MAX_RETRIES
    )

    raise NotamServiceError, "NOTAM API unavailable after #{MAX_RETRIES} retries"
  end

  # Calculate exponential backoff delay with jitter.
  # Respects Retry-After header if present.
  #
  # @param attempt [Integer] the current retry attempt (0-indexed)
  # @param response [Net::HTTPResponse] the HTTP response
  # @return [Float] delay in seconds
  def calculate_backoff(attempt, response)
    # Respect Retry-After header if present (common with 429 responses)
    if response["Retry-After"]
      retry_after = response["Retry-After"].to_f
      return [retry_after, MAX_DELAY].min if retry_after.positive?
    end

    # Exponential backoff with full jitter
    # delay = random(0, min(max_delay, base_delay * 2^attempt))
    max_for_attempt = [BASE_DELAY * (2**attempt), MAX_DELAY].min
    rand * max_for_attempt
  end

  # @param url [String] the request URL
  # @param attempt [Integer] the attempt number
  # @param status [String] the HTTP status code
  # @param outcome [String] the attempt outcome
  # @param delay [Float, nil] the backoff delay
  # @return [void]
  def log_attempt(url, attempt, status, outcome, delay: nil)
    Rails.logger.info(
      event: "notam.api_request",
      attempt: attempt,
      status: status,
      outcome: outcome,
      delay_seconds: delay&.round(2),
      url_host: API_HOST
    )
  end
end

class NotamServiceError < StandardError; end
```

#### Example 9: Exception Handling That Breaks Transaction Integrity

**Source:** https://api.rubyonrails.org/classes/ActiveRecord/Transactions/ClassMethods.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/membership_upgrade_service.rb
class MembershipUpgradeService
  def upgrade(user, new_tier)
    ActiveRecord::Base.transaction do
      membership = user.active_membership
      old_tier = membership.tier

      membership.update!(tier: new_tier)

      # Create audit record inside transaction
      AuditLog.create!(
        user: user,
        action: "membership_upgraded",
        resource_type: "Membership",
        resource_id: membership.id,
        metadata: { old_tier: old_tier, new_tier: new_tier }
      )

      # Send notification inside transaction
      begin
        MembershipMailer.upgrade_confirmation(user: user, tier: new_tier).deliver_now
      rescue Net::SMTPError => e
        # Rescuing inside the transaction swallows the error
        # but the transaction COMMITS with the upgrade applied.
        # The user is upgraded but never notified.
        Rails.logger.error("Email failed: #{e.message}")
      end

      # Update Stripe inside transaction
      begin
        Stripe::Subscription.update(
          membership.stripe_subscription_id,
          { items: [{ id: membership.stripe_item_id, price: price_for(new_tier) }] }
        )
      rescue Stripe::StripeError => e
        # CRITICAL: Catching the Stripe error inside the transaction
        # means the local DB is updated but Stripe is NOT.
        # The user has "premium" in our DB but "basic" in Stripe.
        # They get premium features without paying.
        Rails.logger.error("Stripe update failed: #{e.message}")
      end
    end
  end
end
```

**Secure Fix:**
```ruby
# app/services/membership_upgrade_service.rb
class MembershipUpgradeService
  # Upgrade a user's membership tier with full consistency.
  # Stripe is updated FIRST (source of truth for billing).
  # Local DB is updated only after Stripe confirms.
  # Side effects (email) are deferred to after commit.
  #
  # @param user [User] the user to upgrade
  # @param new_tier [String] the target tier name
  # @return [Membership] the updated membership
  # @raise [MembershipUpgradeError] if upgrade fails at any stage
  def upgrade(user, new_tier)
    membership = user.active_membership
    raise MembershipUpgradeError, "No active membership" if membership.nil?

    old_tier = membership.tier
    raise MembershipUpgradeError, "Already on #{new_tier}" if old_tier == new_tier

    # Step 1: Update Stripe FIRST (source of truth for billing)
    # If this fails, no local changes are made.
    stripe_subscription = update_stripe_subscription(membership, new_tier)

    # Step 2: Update local database only after Stripe succeeds
    ActiveRecord::Base.transaction do
      membership.lock!
      membership.update!(
        tier: new_tier,
        stripe_price_id: stripe_subscription.items.data.first.price.id,
        current_period_end: Time.at(stripe_subscription.current_period_end).utc
      )

      AuditLog.create!(
        user: user,
        action: "membership_upgraded",
        resource_type: "Membership",
        resource_id: membership.id,
        metadata: {
          old_tier: old_tier,
          new_tier: new_tier,
          stripe_subscription_id: membership.stripe_subscription_id
        }
      )
    end

    # Step 3: Side effects AFTER successful commit only
    MembershipMailer.upgrade_confirmation(
      user: user,
      tier: new_tier
    ).deliver_later  # Use deliver_later, not deliver_now in transactions

    Rails.logger.info(
      event: "membership.upgraded",
      user_id: user.id,
      membership_id: membership.id,
      old_tier: old_tier,
      new_tier: new_tier
    )

    membership
  rescue Stripe::CardError => e
    # Payment issue — user's fault, do not retry
    Rails.logger.warn(
      event: "membership.upgrade.payment_failed",
      user_id: user.id,
      error: e.message
    )
    raise MembershipUpgradeError, "Payment failed: #{e.user_message}"
  rescue Stripe::RateLimitError, Stripe::APIConnectionError => e
    # Transient Stripe issue — safe to retry
    Rails.logger.error(
      event: "membership.upgrade.stripe_transient",
      user_id: user.id,
      error_class: e.class.name,
      error: e.message
    )
    raise MembershipUpgradeError, "Payment service temporarily unavailable"
  rescue Stripe::StripeError => e
    # Other Stripe error — log and fail
    Rails.logger.error(
      event: "membership.upgrade.stripe_error",
      user_id: user.id,
      error_class: e.class.name,
      error: e.message
    )
    raise MembershipUpgradeError, "Payment processing error"
  rescue ActiveRecord::RecordInvalid => e
    # DB update failed AFTER Stripe succeeded — inconsistency!
    # Log as critical and trigger reconciliation
    Rails.logger.error(
      event: "membership.upgrade.db_inconsistency",
      user_id: user.id,
      membership_id: membership&.id,
      error: e.message,
      severity: "critical"
    )
    ReconcileStripeMembershipJob.perform_later(user.id)
    raise MembershipUpgradeError, "Upgrade partially completed — support has been notified"
  end

  private

  # Update the Stripe subscription to the new tier.
  #
  # @param membership [Membership] the membership to update
  # @param new_tier [String] the target tier
  # @return [Stripe::Subscription] the updated subscription
  def update_stripe_subscription(membership, new_tier)
    Stripe::Subscription.update(
      membership.stripe_subscription_id,
      {
        items: [{
          id: membership.stripe_item_id,
          price: price_id_for(new_tier)
        }],
        proration_behavior: "create_prorations"
      }
    )
  end

  # @param tier [String] the tier name
  # @return [String] the Stripe price ID
  # @raise [MembershipUpgradeError] if tier is unknown
  def price_id_for(tier)
    price = Rails.application.credentials.dig(:stripe, :"#{tier}_price_id")
    raise MembershipUpgradeError, "Unknown tier: #{tier}" if price.nil?

    price
  end
end

class MembershipUpgradeError < StandardError; end
```

#### Example 10: Active Storage Upload Failure Without Cleanup

**Source:** https://edgeguides.rubyonrails.org/active_storage_overview.html#attaching-file-io-objects
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/evidences_controller.rb
class EvidencesController < ApplicationController
  def create
    @evidence = Evidence.new(evidence_params)
    @evidence.sighting = Sighting.find(params[:sighting_id])
    authorize @evidence

    # If the upload to DigitalOcean Spaces fails mid-transfer:
    # - The Evidence record may be saved without an attachment
    # - Or a partial blob record exists in active_storage_blobs
    # - No cleanup of orphaned blobs
    # - No user feedback about the upload failure
    if @evidence.save
      redirect_to @evidence.sighting
    else
      render :new, status: :unprocessable_entity
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/evidences_controller.rb
class EvidencesController < ApplicationController
  # Create evidence with a file attachment.
  # Handles upload failures gracefully and ensures data consistency.
  #
  # @return [void]
  # @raise [Pundit::NotAuthorizedError] if user lacks permission
  def create
    @sighting = Sighting.find(params[:sighting_id])
    @evidence = @sighting.evidences.build(evidence_params)
    authorize @evidence

    ActiveRecord::Base.transaction do
      @evidence.save!

      if params.dig(:evidence, :file).present?
        attach_file!(@evidence, params[:evidence][:file])
      end
    end

    Rails.logger.info(
      event: "evidence.created",
      evidence_id: @evidence.id,
      sighting_id: @sighting.id,
      has_attachment: @evidence.file.attached?,
      user_id: current_user.id
    )

    redirect_to @sighting
  rescue ActiveStorage::IntegrityError => e
    # File checksum mismatch — possibly corrupted upload
    Rails.logger.error(
      event: "evidence.upload.integrity_error",
      sighting_id: @sighting.id,
      error: e.message
    )
    @evidence.errors.add(:file, "upload was corrupted. Please try again.")
    render :new, status: :unprocessable_entity
  rescue ActiveStorage::FileNotFoundError,
         Aws::S3::Errors::ServiceError => e
    # Storage service unavailable
    Rails.logger.error(
      event: "evidence.upload.storage_error",
      sighting_id: @sighting.id,
      error_class: e.class.name,
      error_message: e.message
    )
    @evidence.errors.add(:file, "could not be uploaded. The storage service is temporarily unavailable.")
    render :new, status: :service_unavailable
  rescue ActiveRecord::RecordInvalid => e
    Rails.logger.warn(
      event: "evidence.validation_failed",
      sighting_id: @sighting.id,
      errors: e.record.errors.full_messages
    )
    render :new, status: :unprocessable_entity
  end

  private

  # Attach a file to evidence with content-type and magic byte validation.
  #
  # @param evidence [Evidence] the evidence record
  # @param uploaded_file [ActionDispatch::Http::UploadedFile] the uploaded file
  # @return [void]
  # @raise [ActiveRecord::RecordInvalid] if file validation fails
  def attach_file!(evidence, uploaded_file)
    # Validate content type from MIME header
    unless uploaded_file.content_type.in?(Evidence::ALLOWED_CONTENT_TYPES)
      evidence.errors.add(:file, "type '#{uploaded_file.content_type}' is not allowed")
      raise ActiveRecord::RecordInvalid, evidence
    end

    # Validate magic bytes match declared content type
    detected_type = MimeMagic.by_magic(uploaded_file.tempfile)&.type
    if detected_type.present? && detected_type != uploaded_file.content_type
      Rails.logger.warn(
        event: "evidence.upload.content_type_mismatch",
        declared: uploaded_file.content_type,
        detected: detected_type,
        user_id: current_user.id
      )
      evidence.errors.add(:file, "content does not match the declared type")
      raise ActiveRecord::RecordInvalid, evidence
    end

    # Validate file size before upload (avoid uploading huge files that will be rejected)
    if uploaded_file.size > 100.megabytes
      evidence.errors.add(:file, "is too large (maximum is 100 MB)")
      raise ActiveRecord::RecordInvalid, evidence
    end

    evidence.file.attach(uploaded_file)
  end

  # @return [ActionController::Parameters]
  def evidence_params
    params.require(:evidence).permit(:description, :evidence_type, :file)
  end
end

# app/jobs/cleanup_orphaned_blobs_job.rb
# Periodic job to clean up Active Storage blobs that are not attached
# to any record (orphaned by failed uploads or deleted records).
class CleanupOrphanedBlobsJob < ApplicationJob
  queue_as :maintenance

  # Remove unattached blobs older than 24 hours.
  #
  # @return [void]
  def perform
    orphaned_blobs = ActiveStorage::Blob
      .left_joins(:attachments)
      .where(active_storage_attachments: { id: nil })
      .where(created_at: ...24.hours.ago)

    count = orphaned_blobs.count

    orphaned_blobs.find_each do |blob|
      blob.purge

      Rails.logger.info(
        event: "storage.orphaned_blob.purged",
        blob_id: blob.id,
        key: blob.key,
        byte_size: blob.byte_size
      )
    rescue StandardError => e
      Rails.logger.error(
        event: "storage.orphaned_blob.purge_failed",
        blob_id: blob.id,
        error_class: e.class.name,
        error_message: e.message
      )
      # Continue purging other blobs — do not let one failure stop cleanup
    end

    Rails.logger.info(
      event: "storage.orphaned_cleanup.completed",
      blobs_purged: count
    )
  end
end
```

## Checklist

- [ ] No `rescue Exception` anywhere in the codebase — always rescue specific exception classes or at most `StandardError`
- [ ] No empty rescue blocks (`rescue => e; end` or `rescue; nil`) — all exceptions are logged with structured context
- [ ] Every `rescue StandardError` block logs the exception class, message, and relevant context (user_id, record_id, etc.)
- [ ] Background jobs (`ApplicationJob` subclasses) declare `retry_on` for transient errors with exponential backoff (`wait: :polynomially_longer`)
- [ ] Background jobs declare `discard_on` for permanent, non-retryable errors (e.g., `ActiveRecord::RecordNotFound`)
- [ ] Background jobs have a final retry exhaustion handler that logs, updates status, and alerts
- [ ] Stripe webhook processing uses pessimistic locking (`lock("FOR UPDATE")`) to prevent TOCTOU race conditions
- [ ] Stripe subscription changes always re-fetch from Stripe API (never trust webhook payload for billing state)
- [ ] External API calls (all 13 enrichment services) implement retry with exponential backoff and jitter
- [ ] External API calls respect `Retry-After` headers when present
- [ ] Deconfliction pipeline handles partial failures: individual API failures do not prevent other APIs from running
- [ ] Enrichment status is tracked per-source with explicit "success", "failed", "unavailable" markers
- [ ] `nil` is handled defensively: use `&.dig()`, `&.[]`, or guard clauses before accessing nested data from API responses
- [ ] Database transactions wrap all related operations; side effects (email, external API) happen AFTER commit
- [ ] `deliver_later` is used instead of `deliver_now` inside or near transactions
- [ ] Stripe is updated BEFORE local DB for billing operations (Stripe is source of truth)
- [ ] If local DB update fails after Stripe succeeds, a reconciliation job is triggered
- [ ] Error messages shown to users never include internal details (SQL, class names, stack traces, file paths)
- [ ] PostGIS query parameters are validated (latitude -90..90, longitude -180..180, radius > 0) before query execution
- [ ] Active Storage uploads validate content-type AND magic bytes before storing
- [ ] Orphaned Active Storage blobs are cleaned up by a periodic maintenance job
- [ ] Controller `rescue_from` blocks are ordered from most specific to least specific
- [ ] `Pundit::NotAuthorizedError` is NEVER caught by a generic `StandardError` rescue — it has its own dedicated handler
