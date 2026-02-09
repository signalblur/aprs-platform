# Skill: rails-conventions

## Trigger

Invoked internally by other agents during the build-feature pipeline. Not typically called directly by the user.

Can also be invoked manually with `/rails-conventions` to display the full conventions reference.

## Description

Project conventions reference for the APRS platform. Defines coding standards, architectural patterns, and workflow requirements that all agents must follow. This is the canonical source of truth for "how we build things" in APRS.

## TDD Workflow

Every feature follows TRUE Test-Driven Development:

1. **Red:** Write a failing test that describes the desired behavior.
2. **Green:** Write the minimal code necessary to make the test pass.
3. **Refactor:** Clean up the code while keeping all tests green.

Rules:
- Never write production code without a failing test first.
- One assertion per test when practical (multiple assertions acceptable for related state checks).
- Test file must exist before the implementation file.
- All tests must pass before any commit: `bundle exec rspec`.
- SimpleCov 100% line coverage is enforced.

## YARD Documentation

All public methods must have YARD documentation:

```ruby
# Submits a new sighting report with geospatial data.
#
# @param sighting_params [ActionController::Parameters] permitted sighting attributes
# @return [Sighting] the created sighting record
# @raise [Pundit::NotAuthorizedError] if the user lacks permission
# @raise [ActiveRecord::RecordInvalid] if validation fails
def create_sighting(sighting_params)
  # implementation
end
```

Requirements:
- `@param` for every parameter with type and description.
- `@return` with type and description.
- `@raise` for every exception the method can raise.
- One-line summary as the first line of the docblock.
- Private methods: YARD docs optional but encouraged for complex logic.

## Pundit Authorization Patterns

### Controller Setup

```ruby
class ApplicationController < ActionController::Base
  include Pundit::Authorization
  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index
end
```

### Policy Structure

```ruby
class SightingPolicy < ApplicationPolicy
  # Role gate: who can perform this action
  # Tier gate: what tier level is required
  def create?
    user.member? || user.investigator? || user.admin?
  end

  def investigate?
    user.investigator? || user.admin?
  end

  def destroy?
    user.admin? || record.submitter == user
  end

  class Scope < ApplicationPolicy::Scope
    def resolve
      if user.admin?
        scope.all
      else
        scope.where(visibility: :public)
             .or(scope.where(submitter: user))
      end
    end
  end
end
```

Rules:
- Every controller action must call `authorize @resource` (or `authorize Resource` for collection actions).
- Every index action must use `policy_scope(Resource)`.
- No `skip_authorization` without a comment explaining the justification.
- Policies check both `user.role` (role gate) and `user.active_membership&.tier` (tier gate) when applicable.

## Strong Parameters Patterns

```ruby
def sighting_params
  params.require(:sighting).permit(
    :shape_id, :description, :duration_seconds,
    :observed_at, :observed_timezone,
    :latitude, :longitude, :altitude_feet,
    :num_witnesses, :media_source,
    :visibility_conditions, :weather_notes
  )
end
```

Rules:
- Never use `params.permit!`.
- Explicit permit list for every controller.
- Nested attributes use `_attributes` suffix with `id` and `_destroy` when needed.
- Sensitive fields (role, stripe_customer_id, etc.) are never in permit lists.

## PostGIS Conventions

### Migration Patterns

```ruby
class AddLocationToSightings < ActiveRecord::Migration[8.1]
  def change
    # Use geography (not geometry) for accurate distance calculations
    add_column :sightings, :location, :st_point, geographic: true, srid: 4326

    # Always add a GiST spatial index
    add_index :sightings, :location, using: :gist
  end
end
```

### Model Patterns

```ruby
class Sighting < ApplicationRecord
  # RGeo factory for geographic (not geometric) points
  GEOGRAPHIC_FACTORY = RGeo::Geographic.spherical_factory(srid: 4326)

  # Setter for creating point from lat/lng
  def location_from_coordinates(latitude, longitude)
    self.location = GEOGRAPHIC_FACTORY.point(longitude, latitude)
  end

  # Scopes for spatial queries
  scope :within_radius, ->(lat, lng, meters) {
    point = GEOGRAPHIC_FACTORY.point(lng, lat)
    where("ST_DWithin(location, ?, ?)", point.to_s, meters)
  }
end
```

Rules:
- SRID 4326 for all geography columns.
- Geography columns (not geometry) for accurate distance calculations on the Earth's surface.
- GiST spatial indexes on all location columns.
- `observed_at` stored as `timestamptz` (UTC in database).
- `observed_timezone` stored as a separate string column (IANA timezone identifier, e.g., "America/New_York").
- Point constructor: `point(longitude, latitude)` — longitude first.

## API Controller Patterns

### Base Controller

```ruby
module Api
  module V1
    class BaseController < ActionController::API
      include Pundit::Authorization
      before_action :authenticate_api_key!
      after_action :verify_authorized, except: :index
      after_action :verify_policy_scoped, only: :index

      private

      # Authenticate via X-API-Key header
      #
      # @return [void]
      # @raise [Api::V1::UnauthorizedError] if the API key is invalid or missing
      def authenticate_api_key!
        key = request.headers["X-API-Key"]
        digest = OpenSSL::Digest::SHA256.hexdigest(key.to_s)
        @api_key = ApiKey.active.find_by(key_digest: digest)
        render_unauthorized unless @api_key
        @api_key&.increment_usage!
      end

      def current_user
        @api_key&.user
      end
    end
  end
end
```

Rules:
- API controllers inherit from `ActionController::API` (no CSRF protection needed).
- Web controllers inherit from `ApplicationController` (CSRF protection required).
- API authentication via `X-API-Key` header, validated against SHA256 digest.
- API keys track monthly usage for quota enforcement.
- API versioning via `Api::V1::` namespace.
- API responses use JSON; web responses use HTML views.
- Never mix API and web authentication in the same controller.

## Devise Configuration

```ruby
# config/initializers/devise.rb (key settings)
config.paranoid = true                    # Don't reveal if email exists
config.password_length = 12..128          # Minimum 12 characters
config.lock_strategy = :failed_attempts
config.maximum_attempts = 5
config.unlock_strategy = :both
config.unlock_in = 30.minutes
config.stretches = Rails.env.test? ? 1 : 12  # bcrypt cost factor
config.sign_in_after_reset_password = false
config.reconfirmable = true
```

Rules:
- Paranoid mode always on (prevents user enumeration).
- Minimum 12-character passwords.
- Account lockout after 5 failed attempts, unlock via email link or auto-unlock after 30 minutes (`:both` strategy).
- bcrypt stretches: 12 in production/development, 1 in test (for speed).
- Do not sign in automatically after password reset.
- Reconfirmable for email changes.

## Stripe Webhook Handling

```ruby
class StripeWebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token
  skip_after_action :verify_authorized

  def create
    # 1. Verify webhook signature
    payload = request.body.read
    sig_header = request.headers["Stripe-Signature"]
    event = Stripe::Webhook.construct_event(
      payload, sig_header, Rails.application.credentials.stripe[:webhook_secret]
    )

    # 2. Idempotency check (handles TOCTOU race with unique constraint rescue)
    return head :ok if StripeWebhookEvent.exists?(stripe_event_id: event.id)
    StripeWebhookEvent.create!(stripe_event_id: event.id, event_type: event.type)
  rescue ActiveRecord::RecordNotUnique
    # Concurrent webhook delivery — another worker already created the record
    return head :ok

    # 3. Re-fetch from Stripe API (never trust payload)
    case event.type
    when "customer.subscription.created", "customer.subscription.updated"
      subscription = Stripe::Subscription.retrieve(event.data.object.id)
      UpdateMembershipFromStripeJob.perform_later(subscription.id)
    when "customer.subscription.deleted"
      subscription = Stripe::Subscription.retrieve(event.data.object.id)
      CancelMembershipFromStripeJob.perform_later(subscription.id)
    end

    head :ok
  rescue Stripe::SignatureVerificationError
    head :bad_request
  end
end
```

Rules:
- Always verify `Stripe-Signature` header.
- Store event IDs in `StripeWebhookEvent` for idempotency.
- Re-fetch data from Stripe API; never trust the webhook payload directly.
- Use pessimistic locking on `Membership` updates: `membership.lock!` before modifying.
- Process heavy work in background jobs (Solid Queue).
- Skip CSRF verification (webhooks are server-to-server).
- `skip_after_action :verify_authorized` is acceptable here with documented justification (Stripe is the caller, not a user).

## Background Job Patterns (Solid Queue)

```ruby
class UpdateMembershipFromStripeJob < ApplicationJob
  queue_as :default
  retry_on Stripe::RateLimitError, wait: :polynomially_longer, attempts: 5
  discard_on Stripe::InvalidRequestError

  # Updates membership from a Stripe subscription.
  #
  # @param subscription_id [String] the Stripe subscription ID
  # @return [void]
  def perform(subscription_id)
    subscription = Stripe::Subscription.retrieve(subscription_id)
    user = User.find_by!(stripe_customer_id: subscription.customer)

    user.membership.with_lock do
      user.membership.update!(
        tier: determine_tier(subscription),
        status: subscription.status,
        current_period_end: Time.zone.at(subscription.current_period_end)
      )
    end
  end
end
```

Rules:
- Use Solid Queue (DB-backed, no Redis dependency).
- Define `retry_on` for transient errors with backoff.
- Define `discard_on` for permanent errors.
- Use `with_lock` for concurrent-sensitive updates.
- YARD docs on `perform` method.
- Jobs should be idempotent (safe to run multiple times).

## Logging Conventions

```ruby
# Good: structured, no PII
Rails.logger.info({
  event: "sighting_created",
  sighting_id: sighting.id,
  shape_id: sighting.shape_id,
  submitter_role: current_user.role
}.to_json)

# Bad: unstructured, contains PII
Rails.logger.info("User #{current_user.email} created sighting at #{sighting.latitude}, #{sighting.longitude}")
```

Rules:
- JSON structured logging via `Rails.logger`.
- Never log PII: email, name, IP address, exact coordinates, phone number.
- Log event name, record IDs, and non-sensitive metadata only.
- Filter sensitive params from logs: `password`, `token`, `key`, `secret`, `stripe`.
- Use appropriate log levels: `info` for business events, `warn` for recoverable issues, `error` for failures.

## Migration Conventions

```ruby
class CreateSightings < ActiveRecord::Migration[8.1]
  def change
    create_table :sightings do |t|
      t.references :submitter, null: true, foreign_key: { to_table: :users }
      t.references :shape, null: false, foreign_key: true
      t.text :description, null: false
      t.integer :duration_seconds
      t.st_point :location, geographic: true, srid: 4326
      t.timestamptz :observed_at, null: false
      t.string :observed_timezone, null: false
      t.timestamps
    end

    add_index :sightings, :location, using: :gist
    add_index :sightings, :observed_at
  end
end
```

Rules:
- Use `def change` for reversible migrations (preferred over `up`/`down`).
- Add foreign key constraints explicitly.
- Add database-level `null: false` constraints where the application requires presence.
- Add indexes for frequently queried columns.
- Use `timestamptz` for all timestamp columns that represent real-world events.
- PostGIS columns use `geographic: true, srid: 4326`.
- GiST indexes for spatial columns.
- If a migration is not reversible, use `def up` / `def down` with explicit rollback logic.

## RSpec Patterns

### Request Specs (Controllers)

```ruby
RSpec.describe "Sightings", type: :request do
  let(:user) { create(:user) }

  describe "POST /sightings" do
    it "creates a sighting with valid params" do
      sign_in user
      post sightings_path, params: { sighting: valid_attributes }
      expect(response).to have_http_status(:created)
    end

    it "returns 403 for unauthorized users" do
      post sightings_path, params: { sighting: valid_attributes }
      expect(response).to have_http_status(:unauthorized)
    end
  end
end
```

### Model Specs

```ruby
RSpec.describe Sighting, type: :model do
  describe "validations" do
    it { is_expected.to validate_presence_of(:description) }
    it { is_expected.to belong_to(:submitter).class_name("User") }
  end

  describe "#within_radius" do
    it "finds sightings within the given radius" do
      nearby = create(:sighting, latitude: 40.0, longitude: -75.0)
      far_away = create(:sighting, latitude: 10.0, longitude: -10.0)
      results = described_class.within_radius(40.0, -75.0, 10_000)
      expect(results).to include(nearby)
      expect(results).not_to include(far_away)
    end
  end
end
```

### Policy Specs

```ruby
RSpec.describe SightingPolicy, type: :policy do
  subject { described_class.new(user, sighting) }

  let(:sighting) { create(:sighting) }

  context "when user is a member" do
    let(:user) { create(:user, role: :member) }

    it { is_expected.to permit_action(:create) }
    it { is_expected.to forbid_action(:destroy) }
  end

  context "when user is an admin" do
    let(:user) { create(:user, role: :admin) }

    it { is_expected.to permit_action(:destroy) }
  end
end
```

### System Specs

```ruby
RSpec.describe "Submitting a sighting", type: :system do
  before do
    driven_by(:selenium_chrome_headless)
  end

  it "allows a logged-in user to submit a sighting" do
    user = create(:user)
    sign_in user
    visit new_sighting_path
    fill_in "Description", with: "Bright light in the sky"
    click_button "Submit"
    expect(page).to have_content("Sighting submitted successfully")
  end
end
```

Rules:
- Request specs for controller behavior (preferred over controller specs).
- Model specs for validations, associations, scopes, and business logic.
- Policy specs for every Pundit policy.
- System specs for critical user workflows.
- Use FactoryBot for test data (`create`, `build`, `build_stubbed`).
- Use `sign_in` helper from Devise test helpers.
- Test both happy path and error cases.
- Test authorization (both permitted and forbidden actions).
- Test edge cases and boundary conditions.

## Service Object Pattern

Service objects encapsulate business logic that spans multiple models or involves complex orchestration.

```ruby
class SightingSubmissionService
  # Submits a new sighting with geospatial data and enqueues enrichment.
  #
  # @param user [User, nil] the submitting user (nil for anonymous)
  # @param params [Hash] the sighting attributes
  # @return [ServiceResult] result object with .success?, .record, .errors
  def self.call(user:, params:)
    new(user: user, params: params).call
  end

  def initialize(user:, params:)
    @user = user
    @params = params
  end

  def call
    sighting = Sighting.new(@params)
    sighting.submitter = @user

    if sighting.save
      EnrichSightingJob.perform_later(sighting.id)
      ServiceResult.new(success: true, record: sighting)
    else
      ServiceResult.new(success: false, errors: sighting.errors)
    end
  end
end
```

Rules:
- Class-based with a `.call` class method as the entry point.
- Constructor receives dependencies; `call` executes the logic.
- Return a result object (not a bare model) so callers can check `.success?` without exceptions.
- YARD docs on `.call` and `#call`.
- One service per business operation. Keep services focused.
- Services live in `app/services/`.
- Never call services from models. Call from controllers or background jobs.

## Global Exception Handling

```ruby
class ApplicationController < ActionController::Base
  include Pundit::Authorization

  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index

  rescue_from Pundit::NotAuthorizedError, with: :forbidden
  rescue_from ActiveRecord::RecordNotFound, with: :not_found
  rescue_from ActionController::ParameterMissing, with: :bad_request

  private

  def forbidden(exception)
    Rails.logger.warn({ event: "unauthorized_access", policy: exception.policy.class.name }.to_json)
    respond_to do |format|
      format.html { redirect_to root_path, alert: "You are not authorized to perform this action." }
      format.json { render json: { error: "Forbidden" }, status: :forbidden }
    end
  end

  def not_found
    respond_to do |format|
      format.html { render file: Rails.public_path.join("404.html"), status: :not_found, layout: false }
      format.json { render json: { error: "Not found" }, status: :not_found }
    end
  end

  def bad_request(exception)
    respond_to do |format|
      format.html { redirect_back fallback_location: root_path, alert: exception.message }
      format.json { render json: { error: exception.message }, status: :bad_request }
    end
  end
end
```

Rules:
- `rescue_from` handlers in `ApplicationController` for common exceptions.
- Always log security-relevant exceptions (Pundit denials).
- Never expose internal error details to users.
- API controllers return JSON error responses; web controllers redirect or render error pages.
- Specific exception classes only — never `rescue StandardError` without re-raising.

## Time Manipulation in Tests

Use `ActiveSupport::Testing::TimeHelpers` exclusively. Do NOT use the `timecop` gem.

```ruby
# Good: freeze time for deterministic tests
it "expires API key after expiration date" do
  key = create(:api_key, expires_at: 1.hour.from_now)
  travel_to 2.hours.from_now do
    expect(ApiKey.active).not_to include(key)
  end
end

# Good: travel to a specific time
it "resets monthly usage on the first of the month" do
  travel_to Time.zone.local(2026, 2, 1, 0, 0, 0) do
    ResetApiUsageJob.perform_now
    expect(api_key.reload.monthly_usage).to eq(0)
  end
end
```

Rules:
- Use `travel_to`, `freeze_time`, and `travel` from `ActiveSupport::Testing::TimeHelpers`.
- Prohibit `timecop` gem — one time manipulation library only.
- Always use `travel_to` for time-dependent logic: API key expiry, Stripe grace periods, webhook signature tolerance, circuit breaker resets, monthly quota resets.
- Include `ActiveSupport::Testing::TimeHelpers` in `spec/support/time_helpers.rb` for all spec types.

## Code Style Rules

- Methods: maximum 20 lines.
- Classes: maximum 200 lines.
- Maximum 3 levels of nesting.
- No N+1 queries: use `.includes()`, `.eager_load()`, or `.preload()`.
- Use specific exception classes; rescue specific exceptions (never `rescue StandardError` without re-raising).
- Filter sensitive params: `config.filter_parameters += [:password, :token, :key, :api_key, :secret, :stripe, :name, :first_name, :last_name, :contact_info, :phone, :latitude, :longitude]`.
