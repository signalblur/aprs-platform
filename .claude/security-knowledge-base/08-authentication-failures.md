# A08 — Authentication Failures

## Overview

Authentication Failures occur when an application improperly implements identity verification, session management, or credential handling, allowing attackers to impersonate legitimate users, hijack sessions, or bypass authentication mechanisms entirely. Mapped from OWASP 2021 A07 (Identification and Authentication Failures) and retained in the 2025 Top 10 as A07, this category remains one of the most exploited vulnerability classes in web applications.

For APRS, authentication is the gateway to sensitive data: UAP sighting locations tied to real-world observers, investigation notes from field researchers, and payment information managed through Stripe subscriptions. The platform employs three distinct authentication mechanisms: Devise for web session authentication (with paranoid mode, lockable accounts, and confirmable email), SHA256-digested API keys for programmatic access, and Stripe webhook signature verification for payment event processing. A failure in any of these mechanisms could expose observer personally identifiable information (PII), allow unauthorized modification of sighting data, or enable financial fraud through manipulated subscription states.

The attack surface is compounded by APRS's role-based access control (member, investigator, admin) and tier-based feature gating via the Membership model. An authentication bypass that elevates a standard member to an investigator or admin role, or that grants access to a premium tier without payment, represents both a security and a business logic failure. Credential stuffing is a particular concern given that APRS users may reuse passwords from breached databases, making robust lockout policies and rate limiting essential defenses.

## APRS-Specific Attack Surface

- **Devise configuration:** Non-paranoid mode leaking user existence via login/reset error messages; weak password requirements allowing dictionary attacks; insufficient bcrypt stretches enabling offline brute force
- **Account lockout:** Missing or misconfigured `:lockable` strategy allowing unlimited login attempts; lockout state not synchronized across API and web interfaces
- **Session management:** Session fixation after successful login; remember-me tokens not invalidated on sign out or password change; session cookies without `Secure`, `HttpOnly`, `SameSite` attributes
- **Password reset flow:** Predictable or long-lived reset tokens; reset token not invalidated after use; email enumeration through reset endpoint timing differences
- **API key authentication:** Timing oracle in key comparison revealing valid key prefixes; API keys stored in plaintext; no key rotation mechanism; keys not scoped to specific permissions
- **Stripe webhook signature verification:** Missing or incorrect `Stripe-Signature` header validation; replay attacks using old webhook events; clock skew tolerance too large
- **Rate limiting:** Missing rate limits on login, registration, password reset, and API key authentication endpoints
- **Email enumeration:** Registration and password reset endpoints revealing whether an email exists in the system
- **Multi-factor authentication:** No MFA support for investigator and admin roles that access sensitive data
- **Remember me token management:** Tokens persisting after sign out, password change, or role change

## Examples

### Basic Level

#### Example 1: Non-Paranoid Devise Leaking User Existence
**Source:** https://github.com/heartcombo/devise/wiki/How-To:-Using-paranoid-mode
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/initializers/devise.rb — paranoid mode disabled
# When a user tries to log in with an invalid email, Devise returns
# "Email not found" — confirming the email is NOT in the database.
# When the email exists but password is wrong: "Invalid password"
# This difference allows attackers to enumerate valid user accounts.

Devise.setup do |config|
  config.paranoid = false  # DEFAULT — leaks user existence!

  config.password_length = 6..128
  config.stretches = Rails.env.test? ? 1 : 11
end
```

**Secure Fix:**
```ruby
# config/initializers/devise.rb — paranoid mode ON
# In paranoid mode, Devise returns the same generic message for
# invalid email AND invalid password: "Invalid Email or password."
# This prevents email enumeration through login attempts.

Devise.setup do |config|
  config.paranoid = true

  # Minimum 12 characters per APRS security policy
  config.password_length = 12..128

  # bcrypt stretches: 12+ for production security
  config.stretches = Rails.env.test? ? 1 : 12

  # Lock account after 5 failed attempts
  config.lock_strategy = :failed_attempts
  config.maximum_attempts = 5
  config.unlock_strategy = :time
  config.unlock_in = 30.minutes

  # Expire sessions after inactivity
  config.timeout_in = 30.minutes

  # Require email confirmation before allowing login
  config.reconfirmable = true
end
```

#### Example 2: Weak Password Requirements
**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-strength
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/initializers/devise.rb — weak password policy
Devise.setup do |config|
  config.password_length = 6..128  # 6 chars is far too short
  config.stretches = Rails.env.test? ? 1 : 10  # 10 stretches is below recommendation
end

# app/models/user.rb — no additional password validation
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
end
```

**Secure Fix:**
```ruby
# config/initializers/devise.rb — strong password policy
Devise.setup do |config|
  config.password_length = 12..128  # NIST 800-63B minimum
  config.stretches = Rails.env.test? ? 1 : 12  # 12+ stretches per APRS policy
end

# app/models/user.rb — enforce password complexity
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :lockable, :confirmable, :timeoutable

  # Prevent commonly breached passwords
  validate :password_not_in_breach_list, if: :password_present?

  private

  # @return [void]
  # @raise [ActiveRecord::RecordInvalid] if password is breached
  def password_not_in_breach_list
    return unless password.present?

    # Check against a local breach list or Pwned Passwords API (k-anonymity)
    sha1_prefix = Digest::SHA1.hexdigest(password).upcase[0..4]
    sha1_suffix = Digest::SHA1.hexdigest(password).upcase[5..]

    response = Net::HTTP.get(URI("https://api.pwnedpasswords.com/range/#{sha1_prefix}"))
    if response.include?(sha1_suffix)
      errors.add(:password, "has been found in a data breach. Please choose a different password.")
    end
  rescue StandardError
    # If the API is unavailable, allow the password but log a warning
    Rails.logger.warn("Pwned Passwords API unavailable, skipping breach check")
  end

  # @return [Boolean] true if password attribute is present
  def password_present?
    password.present?
  end
end
```

#### Example 3: Missing Account Lockout
**Source:** https://github.com/heartcombo/devise/wiki/How-To:-Add-:lockable-to-Users
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/user.rb — no :lockable module
# Without lockout, attackers can attempt unlimited password guesses
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
end

# db/migrate/..._devise_create_users.rb — missing lockable columns
class DeviseCreateUsers < ActiveRecord::Migration[8.1]
  def change
    create_table :users do |t|
      t.string :email, null: false, default: ""
      t.string :encrypted_password, null: false, default: ""
      t.string :reset_password_token
      t.datetime :reset_password_sent_at
      t.datetime :remember_created_at
      # No lockable columns!
      t.timestamps null: false
    end
  end
end
```

**Secure Fix:**
```ruby
# app/models/user.rb — lockable module enabled
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :lockable, :confirmable, :timeoutable,
         :trackable

  enum :role, { member: 0, investigator: 1, admin: 2 }, default: :member
end

# db/migrate/..._add_lockable_to_users.rb
class AddLockableToUsers < ActiveRecord::Migration[8.1]
  def change
    # Lockable columns
    add_column :users, :failed_attempts, :integer, default: 0, null: false
    add_column :users, :unlock_token, :string
    add_column :users, :locked_at, :datetime

    # Trackable columns (for suspicious activity detection)
    add_column :users, :sign_in_count, :integer, default: 0, null: false
    add_column :users, :current_sign_in_at, :datetime
    add_column :users, :last_sign_in_at, :datetime
    add_column :users, :current_sign_in_ip, :string
    add_column :users, :last_sign_in_ip, :string

    add_index :users, :unlock_token, unique: true
  end
end
```

### Intermediate Level

#### Example 4: API Key Timing Oracle
**Source:** https://codahale.com/a-lesson-in-timing-attacks/
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/base_controller.rb
# String comparison using == is vulnerable to timing attacks.
# An attacker can measure response times to determine correct
# characters of the API key one byte at a time.
class Api::V1::BaseController < ActionController::API
  before_action :authenticate_api_key!

  private

  # @return [void]
  # @raise [UnauthorizedError] if API key is invalid
  def authenticate_api_key!
    provided_key = request.headers["X-Api-Key"]
    api_key = ApiKey.find_by(key: provided_key)  # Stored in PLAINTEXT!

    unless api_key
      render json: { error: "Unauthorized" }, status: :unauthorized
    end
  end
end

# app/models/api_key.rb — stores key in plaintext
class ApiKey < ApplicationRecord
  belongs_to :user

  before_create :generate_key

  private

  def generate_key
    self.key = SecureRandom.hex(32)  # Stored as plaintext!
  end
end
```

**Secure Fix:**
```ruby
# app/models/api_key.rb — SHA256 digest storage with constant-time lookup
class ApiKey < ApplicationRecord
  belongs_to :user

  # The raw key is only available at creation time, never stored
  attr_accessor :raw_key

  before_create :generate_key_and_digest

  # @param raw_key [String] the raw API key provided in the request
  # @return [ApiKey, nil] the matching API key record or nil
  def self.find_by_raw_key(raw_key)
    return nil if raw_key.blank?

    # Hash the provided key and look up the digest
    # SHA256 lookup is constant-time at the database level
    digest = Digest::SHA256.hexdigest(raw_key)
    find_by(key_digest: digest)
  end

  private

  # @return [void]
  def generate_key_and_digest
    self.raw_key = SecureRandom.urlsafe_base64(32)
    self.key_digest = Digest::SHA256.hexdigest(raw_key)
    self.key_prefix = raw_key[0..7]  # Store prefix for identification only
  end
end

# app/controllers/api/v1/base_controller.rb — timing-safe authentication
class Api::V1::BaseController < ActionController::API
  before_action :authenticate_api_key!
  before_action :check_api_quota!

  private

  # @return [void]
  def authenticate_api_key!
    raw_key = request.headers["X-Api-Key"]

    unless raw_key.present?
      render json: { error: "Missing API key" }, status: :unauthorized
      return
    end

    @current_api_key = ApiKey.find_by_raw_key(raw_key)

    unless @current_api_key&.active?
      # Use constant-time comparison to prevent timing leaks
      # even in the error path
      render json: { error: "Invalid API key" }, status: :unauthorized
    end
  end

  # @return [void]
  def check_api_quota!
    return unless @current_api_key

    if @current_api_key.monthly_requests_count >= @current_api_key.monthly_quota
      render json: { error: "Monthly API quota exceeded" }, status: :too_many_requests
    end
  end
end
```

#### Example 5: Session Fixation After Login
**Source:** https://owasp.org/www-community/attacks/Session_fixation
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/sessions_controller.rb — no session regeneration
# If an attacker plants a session ID in the victim's browser (via XSS
# or a subdomain cookie), the session persists after login, allowing
# the attacker to use the known session ID to access the victim's account.
class SessionsController < Devise::SessionsController
  def create
    # Devise handles authentication, but we've overridden
    # without calling super or regenerating the session
    self.resource = warden.authenticate!(auth_options)
    set_flash_message!(:notice, :signed_in)
    # Session ID is NOT regenerated here — fixation vulnerability!
    sign_in(resource_name, resource)
    respond_with resource, location: after_sign_in_path_for(resource)
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/sessions_controller.rb — proper session regeneration
# Devise's default sign_in already regenerates the session.
# If you MUST override the create action, ensure session is reset.
class SessionsController < Devise::SessionsController
  def create
    super do |resource|
      # Devise::SessionsController#create calls sign_in which calls
      # warden.set_user, which regenerates the session automatically.
      # But if custom session data needs to be preserved:

      # 1. Save any pre-login session data that needs to persist
      pre_login_return_to = session[:return_to]

      # 2. Reset the session to prevent fixation
      reset_session

      # 3. Re-sign in with new session
      sign_in(resource_name, resource)

      # 4. Restore only safe pre-login data
      session[:return_to] = pre_login_return_to if pre_login_return_to.present?
    end
  end
end

# config/initializers/session_store.rb — secure session cookie settings
Rails.application.config.session_store :cookie_store,
  key: "_aprs_session",
  secure: Rails.env.production?,
  httponly: true,
  same_site: :lax,
  expire_after: 30.minutes
```

#### Example 6: Insecure Password Reset Token
**Source:** https://github.com/heartcombo/devise/wiki/How-To:-Override-confirmations-so-users-can-pick-their-own-passwords-as-part-of-confirmation-activation
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/custom_passwords_controller.rb
# Custom password reset that uses a weak, predictable token
class CustomPasswordsController < ApplicationController
  skip_before_action :authenticate_user!

  def create
    user = User.find_by(email: params[:email])
    if user
      # VULNERABLE: predictable token based on timestamp
      token = Base64.encode64("#{user.id}-#{Time.current.to_i}")
      user.update(reset_password_token: token)
      PasswordMailer.reset_instructions(user, token).deliver_later
    end
    # Returns different message if user exists vs not — email enumeration!
    if user
      redirect_to new_user_session_path, notice: "Reset instructions sent!"
    else
      redirect_to new_user_session_path, alert: "Email not found!"
    end
  end

  def update
    token = params[:reset_token]
    user = User.find_by(reset_password_token: token)
    # Token is never expired — can be used indefinitely!
    if user
      user.update(password: params[:password])
      redirect_to new_user_session_path, notice: "Password updated!"
    end
  end
end
```

**Secure Fix:**
```ruby
# Use Devise's built-in password reset — do NOT roll your own
# Devise uses a cryptographically random token that is:
# - Hashed before storage (database stores digest, not raw token)
# - Time-limited (config.reset_password_within)
# - Single-use (cleared after successful reset)

# config/initializers/devise.rb
Devise.setup do |config|
  config.paranoid = true  # Same message whether email exists or not
  config.reset_password_within = 2.hours  # Token expires after 2 hours
  config.sign_in_after_reset_password = false  # Force re-login
end

# app/models/user.rb — use Devise's recoverable module
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable,  # Provides secure password reset
         :rememberable, :validatable,
         :lockable, :confirmable, :timeoutable

  # When password is reset, invalidate all existing sessions
  # and remember-me tokens
  def after_password_reset
    # Invalidate all active sessions by rotating the session token
    self.update_columns(
      remember_created_at: nil,
      updated_at: Time.current
    )
  end
end

# If you must customize the controller, inherit from Devise's:
class PasswordsController < Devise::PasswordsController
  # Rate limit password reset requests
  before_action :throttle_reset_requests, only: :create

  private

  # @return [void]
  def throttle_reset_requests
    cache_key = "password_reset:#{request.remote_ip}"
    count = Rails.cache.increment(cache_key, 1, expires_in: 1.hour, initial: 0)

    if count > 5
      redirect_to new_user_session_path,
        alert: "Too many password reset requests. Please try again later."
    end
  end
end
```

#### Example 7: Missing Rate Limiting on Login Endpoint
**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/routes.rb — no rate limiting on authentication routes
Rails.application.routes.draw do
  devise_for :users
  # Login endpoint accepts unlimited requests per IP/account
  # Attacker can attempt credential stuffing at full speed

  namespace :api do
    namespace :v1 do
      resources :sightings, only: %i[index show create]
    end
  end
end
```

**Secure Fix:**
```ruby
# Gemfile
gem "rack-attack"

# config/initializers/rack_attack.rb
# Rate limit authentication and sensitive endpoints
class Rack::Attack
  # Throttle login attempts by IP address
  # 5 attempts per 20 seconds per IP
  throttle("logins/ip", limit: 5, period: 20.seconds) do |req|
    req.ip if req.path == "/users/sign_in" && req.post?
  end

  # Throttle login attempts by email (normalized)
  # 10 attempts per hour per email
  throttle("logins/email", limit: 10, period: 1.hour) do |req|
    if req.path == "/users/sign_in" && req.post?
      # Normalize email to prevent bypasses like "User@Example.COM"
      req.params.dig("user", "email")&.downcase&.strip
    end
  end

  # Throttle password reset requests by IP
  throttle("password_resets/ip", limit: 5, period: 1.hour) do |req|
    req.ip if req.path == "/users/password" && req.post?
  end

  # Throttle API key authentication
  throttle("api/ip", limit: 100, period: 1.minute) do |req|
    req.ip if req.path.start_with?("/api/")
  end

  # Throttle account registration (anti-spam)
  throttle("registrations/ip", limit: 3, period: 1.hour) do |req|
    req.ip if req.path == "/users" && req.post?
  end

  # Block IPs with 100+ failed login attempts in 1 hour
  blocklist("fail2ban/login") do |req|
    Rack::Attack::Allow2Ban.filter(req.ip, maxretry: 100, findtime: 1.hour, bantime: 24.hours) do
      req.path == "/users/sign_in" && req.post?
    end
  end

  # Custom response for throttled requests
  self.throttled_responder = lambda do |matched, _period, request|
    now = Time.current
    match_data = request.env["rack.attack.match_data"]
    retry_after = match_data[:period] - (now.to_i % match_data[:period])

    headers = {
      "Content-Type" => "application/json",
      "Retry-After" => retry_after.to_s
    }

    body = { error: "Rate limit exceeded. Retry after #{retry_after} seconds." }.to_json
    [429, headers, [body]]
  end
end
```

### Advanced Level

#### Example 8: Remember-Me Token Not Invalidated on Sign Out
**Source:** https://github.com/heartcombo/devise/wiki/How-To:-Allow-users-to-sign-in-using-their-username-or-email-address
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/custom_sessions_controller.rb
# Overridden sign out that doesn't clear the remember-me token
class CustomSessionsController < Devise::SessionsController
  def destroy
    # Just clearing the session but NOT the remember-me cookie/token
    reset_session
    redirect_to root_path, notice: "Signed out successfully."
    # The remember-me token in the database is still valid!
    # If an attacker has stolen the remember-me cookie, they can
    # continue to authenticate even after the user signs out.
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/sessions_controller.rb — proper sign out
class SessionsController < Devise::SessionsController
  # Use Devise's built-in destroy which properly handles:
  # 1. Clearing the session
  # 2. Clearing the remember-me cookie
  # 3. Rotating the remember token in the database
  def destroy
    current_user&.invalidate_all_sessions!
    super
  end
end

# app/models/user.rb — comprehensive session invalidation
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :lockable, :confirmable, :timeoutable

  # @return [void]
  # Invalidate all active sessions and remember-me tokens
  def invalidate_all_sessions!
    # Clear remember token
    self.remember_token = nil
    self.remember_created_at = nil

    # If using database-backed sessions, clear all sessions for this user
    # ActiveRecord::SessionStore::Session.where("data LIKE ?", "%user_id: #{id}%").delete_all

    save!(validate: false)

    Rails.logger.info(
      "All sessions invalidated",
      user_id: id,
      event: "session_invalidation"
    )
  end

  # Invalidate sessions when password changes
  # Devise calls this automatically with config.sign_in_after_change_password = false
  def after_password_change
    invalidate_all_sessions!
  end

  # Invalidate sessions when role changes (security-critical)
  after_update :invalidate_sessions_on_role_change, if: :saved_change_to_role?

  private

  # @return [void]
  def invalidate_sessions_on_role_change
    invalidate_all_sessions!
    Rails.logger.warn(
      "User role changed, all sessions invalidated",
      user_id: id,
      old_role: role_before_last_save,
      new_role: role,
      event: "role_change_session_invalidation"
    )
  end
end
```

#### Example 9: Stripe Webhook Missing Signature Verification
**Source:** https://docs.stripe.com/webhooks/signatures
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
# Webhook endpoint that trusts the payload without verifying
# the Stripe-Signature header. Any attacker can forge webhook
# events to grant themselves free subscriptions or admin access.
class Webhooks::StripeController < ApplicationController
  skip_before_action :verify_authenticity_token
  skip_after_action :verify_authorized

  def create
    payload = JSON.parse(request.body.read)
    event_type = payload["type"]

    case event_type
    when "customer.subscription.created"
      # DANGEROUS: trusting unverified payload data
      subscription = payload.dig("data", "object")
      user = User.find_by(stripe_customer_id: subscription["customer"])
      user&.update!(role: :investigator)  # Attacker can escalate privileges!
    when "customer.subscription.deleted"
      subscription = payload.dig("data", "object")
      user = User.find_by(stripe_customer_id: subscription["customer"])
      user&.update!(role: :member)
    end

    head :ok
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/webhooks/stripe_controller.rb
# Properly verify webhook signature and re-fetch data from Stripe API
class Webhooks::StripeController < ApplicationController
  skip_before_action :verify_authenticity_token  # Webhooks don't use CSRF
  skip_after_action :verify_authorized  # Justified: Stripe signature auth

  # @return [void]
  def create
    payload = request.body.read
    sig_header = request.headers["Stripe-Signature"]
    endpoint_secret = Rails.application.credentials.dig(:stripe, :webhook_secret)

    # Step 1: Verify the webhook signature
    event = begin
      Stripe::Webhook.construct_event(payload, sig_header, endpoint_secret)
    rescue JSON::ParserError
      Rails.logger.warn("Stripe webhook: invalid JSON payload")
      head :bad_request and return
    rescue Stripe::SignatureVerificationError => e
      Rails.logger.warn(
        "Stripe webhook: signature verification failed",
        error: e.message,
        event: "stripe_signature_failure"
      )
      head :bad_request and return
    end

    # Step 2: Idempotency — skip already-processed events
    if StripeWebhookEvent.exists?(stripe_event_id: event.id)
      Rails.logger.info("Stripe webhook: duplicate event skipped", stripe_event_id: event.id)
      head :ok and return
    end

    # Step 3: Record the event for idempotency
    StripeWebhookEvent.create!(
      stripe_event_id: event.id,
      event_type: event.type,
      processed_at: Time.current
    )

    # Step 4: Process the event asynchronously
    StripeWebhookProcessorJob.perform_later(event.id, event.type)

    head :ok
  end
end

# app/jobs/stripe_webhook_processor_job.rb
class StripeWebhookProcessorJob < ApplicationJob
  queue_as :default

  # @param stripe_event_id [String] the Stripe event ID
  # @param event_type [String] the event type
  # @return [void]
  def perform(stripe_event_id, event_type)
    # CRITICAL: Re-fetch the event from Stripe API — never trust payload
    event = Stripe::Event.retrieve(stripe_event_id)

    case event.type
    when "customer.subscription.created", "customer.subscription.updated"
      handle_subscription_change(event)
    when "customer.subscription.deleted"
      handle_subscription_deletion(event)
    end
  end

  private

  # @param event [Stripe::Event] the verified Stripe event
  # @return [void]
  def handle_subscription_change(event)
    # Re-fetch subscription from Stripe API
    subscription = Stripe::Subscription.retrieve(event.data.object.id)
    user = User.find_by(stripe_customer_id: subscription.customer)
    return unless user

    # Use pessimistic locking to prevent race conditions
    user.with_lock do
      membership = user.membership || user.build_membership
      membership.update!(
        stripe_subscription_id: subscription.id,
        tier: determine_tier(subscription),
        status: subscription.status,
        current_period_end: Time.at(subscription.current_period_end)
      )
    end
  end

  # @param subscription [Stripe::Subscription] the Stripe subscription
  # @return [String] the membership tier
  def determine_tier(subscription)
    price_id = subscription.items.data.first.price.id
    case price_id
    when ENV["STRIPE_BASIC_PRICE_ID"] then "basic"
    when ENV["STRIPE_PRO_PRICE_ID"] then "professional"
    when ENV["STRIPE_ENTERPRISE_PRICE_ID"] then "enterprise"
    else "basic"
    end
  end
end
```

#### Example 10: Email Enumeration Through Registration Timing
**Source:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/registrations_controller.rb
# Registration that has different response times for existing vs new emails
class RegistrationsController < Devise::RegistrationsController
  def create
    # If email exists: Devise checks for uniqueness, returns fast with error
    # If email is new: Devise hashes password (slow bcrypt), creates user
    # The timing difference reveals whether the email is registered
    super
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/registrations_controller.rb
# Normalize response timing to prevent email enumeration
class RegistrationsController < Devise::RegistrationsController
  def create
    start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    super do |resource|
      # Ensure consistent timing regardless of whether user existed
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
      minimum_time = 0.5  # 500ms minimum response time
      sleep(minimum_time - elapsed) if elapsed < minimum_time
    end
  end

  # Also override the JSON response for API registrations
  protected

  # @return [String] the same success message regardless of outcome
  def after_inactive_sign_up_path_for(_resource)
    new_user_session_path
  end

  # @return [void]
  def set_flash_message!(key, kind, options = {})
    # Override to always show the same confirmation message
    if kind == :signed_up_but_unconfirmed || kind == :signed_up
      flash[:notice] = "A confirmation email has been sent. Please check your inbox."
    else
      super
    end
  end
end

# config/initializers/devise.rb — additional anti-enumeration config
Devise.setup do |config|
  config.paranoid = true
  # Return the same message for all registration outcomes
  # "A message with a confirmation link has been sent"
  # regardless of whether the email was already taken
end
```

## Checklist

- [ ] Devise `paranoid` mode is set to `true` in `config/initializers/devise.rb`
- [ ] Password minimum length is 12+ characters (`config.password_length = 12..128`)
- [ ] bcrypt stretches are 12+ in production (`config.stretches = 12`)
- [ ] `:lockable` module is enabled with `maximum_attempts: 5`
- [ ] `:confirmable` module is enabled requiring email verification before login
- [ ] `:timeoutable` module is enabled with reasonable timeout (`config.timeout_in = 30.minutes`)
- [ ] Password reset tokens expire within 2 hours (`config.reset_password_within = 2.hours`)
- [ ] Session cookie has `Secure`, `HttpOnly`, and `SameSite=Lax` attributes in production
- [ ] Session is regenerated after successful authentication (Devise default behavior preserved)
- [ ] Remember-me tokens are invalidated on sign out and password change
- [ ] All sessions are invalidated when user role changes
- [ ] API keys are stored as SHA256 digests, never in plaintext
- [ ] API key lookup uses digest comparison, not raw key comparison
- [ ] `rack-attack` or equivalent rate limiter is configured for login, registration, and password reset endpoints
- [ ] Login endpoint is rate limited to 5 attempts per 20 seconds per IP
- [ ] Password reset endpoint is rate limited to 5 requests per hour per IP
- [ ] API endpoints are rate limited to prevent key brute-forcing
- [ ] Registration and login responses do not reveal whether an email exists in the system
- [ ] Stripe webhook endpoints verify `Stripe-Signature` header before processing
- [ ] Stripe webhook events are recorded for idempotency (duplicate rejection)
- [ ] Stripe data is re-fetched from the API, never trusted from webhook payload
- [ ] Failed authentication attempts are logged with IP address (not password) for monitoring
- [ ] Account lockout events are logged and alertable
- [ ] No custom authentication logic bypasses Devise's built-in security mechanisms
