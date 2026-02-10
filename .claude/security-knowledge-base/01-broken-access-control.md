# A01 — Broken Access Control

## Overview

Broken Access Control is the most critical web application security risk according to OWASP's 2021 and 2025 Top 10 rankings. It occurs when users can act outside their intended permissions — accessing other users' data, escalating privileges, or bypassing authorization checks entirely. In the 2021 analysis, 94% of applications tested had some form of broken access control, with over 318,000 occurrences mapped to this category.

For APRS, broken access control is particularly dangerous because the platform handles sensitive UAP sighting data with multi-layered access: three user roles (member, investigator, admin), three membership tiers (basic, premium, platinum) that gate feature access, ownership-based access to sightings and evidence, and API key-scoped access for programmatic consumers. A single missing `authorize` call or misconfigured Pundit policy could expose witness contact information, investigation notes, or allow unauthorized users to modify sighting records.

The Rails + Pundit combination provides strong guardrails when used correctly — `verify_authorized` and `verify_policy_scoped` after-action hooks catch missing authorization calls at the controller level. However, these protections only work if they are never bypassed with `skip_authorization` and if Pundit policies themselves correctly implement the business logic for every role-tier combination.

## APRS-Specific Attack Surface

- **Missing Pundit `authorize` calls** — Any controller action without `authorize @record` silently permits all authenticated users to perform the action. The `verify_authorized` after-action hook catches this only if it is not skipped.
- **IDOR (Insecure Direct Object Reference) on Sightings** — Sightings are accessed by database ID. Without ownership checks in Pundit policies, any user can view, edit, or delete another user's sighting by guessing or enumerating IDs.
- **Role escalation via mass assignment** — If the `role` attribute is not excluded from strong parameters, a user can send `user[role]=admin` in a request to escalate their privileges.
- **Membership tier bypass** — Premium features (e.g., advanced search, bulk export, spatial analysis) gated by membership tier can be accessed if policies check `user.role` but forget to check `user.active_membership&.tier`.
- **Investigation assignment abuse** — Investigators should only access investigations assigned to them. Without scoping, an investigator could access all investigations across the platform.
- **Active Storage direct URL exposure** — Active Storage generates signed URLs for file access. If the signing configuration is too permissive or blob access is not scoped through authorization, evidence files (photos, videos) can be accessed by unauthenticated users.
- **API key scope escalation** — API keys may be scoped to read-only or specific resources. Without server-side enforcement of scopes, an API consumer could perform write operations or access resources outside their granted scope.
- **Admin panel access** — Admin-only routes (user management, audit logs, system configuration) must check `user.admin?` in both routing constraints and Pundit policies.
- **`skip_authorization` abuse** — Developers may add `skip_authorization` to avoid Pundit errors during development and forget to remove it, permanently disabling access control for that action.
- **Stripe webhook authorization** — Webhook endpoints that modify Membership records must verify the Stripe signature and re-fetch data from Stripe API. Trusting webhook payloads directly allows attackers to forge upgrade events.

## Examples

### Basic Level

#### Example 1: Missing Pundit `authorize` Call in Controller Action

**Source:** https://github.com/varvet/pundit#ensuring-policies-and-scopes-are-used
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/sightings_controller.rb
# VULNERABLE: No authorize call — any authenticated user can update any sighting
class SightingsController < ApplicationController
  before_action :authenticate_user!

  def update
    @sighting = Sighting.find(params[:id])
    # Missing: authorize @sighting
    if @sighting.update(sighting_params)
      redirect_to @sighting, notice: "Sighting updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  private

  def sighting_params
    params.require(:sighting).permit(:title, :description, :observed_at)
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/sightings_controller.rb
# SECURE: Pundit authorize enforces policy check; verify_authorized catches omissions
class SightingsController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index

  # @param id [Integer] sighting ID from URL params
  # @return [void]
  def update
    @sighting = Sighting.find(params[:id])
    authorize @sighting
    if @sighting.update(sighting_params)
      redirect_to @sighting, notice: "Sighting updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  private

  # @return [ActionController::Parameters] permitted sighting attributes
  def sighting_params
    params.require(:sighting).permit(:title, :description, :observed_at)
  end
end
```

#### Example 2: IDOR — Accessing Another User's Sighting

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/policies/sighting_policy.rb
# VULNERABLE: show? returns true for all authenticated users — any user can view
# any sighting including draft/private sightings they don't own
class SightingPolicy < ApplicationPolicy
  def show?
    true
  end

  def update?
    true
  end

  def destroy?
    true
  end
end
```

**Secure Fix:**
```ruby
# app/policies/sighting_policy.rb
# SECURE: Ownership check for mutations; published sightings are public,
# but only owners and investigators/admins can see drafts
class SightingPolicy < ApplicationPolicy
  # @return [Boolean] whether the user can view this sighting
  def show?
    record.published? || owner? || investigator_or_admin?
  end

  # @return [Boolean] whether the user can update this sighting
  def update?
    owner? || user.admin?
  end

  # @return [Boolean] whether the user can destroy this sighting
  def destroy?
    owner? || user.admin?
  end

  # Scope limits which sightings appear in index listings
  class Scope < ApplicationPolicy::Scope
    # @return [ActiveRecord::Relation] scoped sightings
    def resolve
      if user.admin?
        scope.all
      elsif user.investigator?
        scope.where(published: true).or(scope.where(submitter: user))
      else
        scope.where(published: true).or(scope.where(submitter: user))
      end
    end
  end

  private

  # @return [Boolean] whether the current user is the sighting owner
  def owner?
    record.submitter_id == user.id
  end

  # @return [Boolean] whether the current user is an investigator or admin
  def investigator_or_admin?
    user.investigator? || user.admin?
  end
end
```

#### Example 3: Role Escalation via Mass Assignment

**Source:** https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/registrations_controller.rb
# VULNERABLE: role is included in permitted params — user can self-assign admin
class RegistrationsController < Devise::RegistrationsController
  private

  def sign_up_params
    params.require(:user).permit(:email, :password, :password_confirmation, :role)
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/registrations_controller.rb
# SECURE: role is never user-assignable — only admins can change roles
# via a separate admin-only endpoint
class RegistrationsController < Devise::RegistrationsController
  private

  # @return [ActionController::Parameters] permitted registration attributes
  def sign_up_params
    params.require(:user).permit(:email, :password, :password_confirmation)
  end
end

# app/controllers/admin/users_controller.rb
# Role changes are admin-only operations
class Admin::UsersController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_authorized

  # @return [void]
  def update_role
    @user = User.find(params[:id])
    authorize @user, :update_role?
    if @user.update(role: params[:user][:role])
      AuditLog.create!(
        actor: current_user,
        action: "role_change",
        target: @user,
        metadata: { new_role: @user.role }
      )
      redirect_to admin_user_path(@user), notice: "Role updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end
end
```

### Intermediate Level

#### Example 4: Active Storage Direct URL Access Without Authorization

**Source:** https://edgeguides.rubyonrails.org/active_storage_overview.html#proxy-mode
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/routes.rb
# VULNERABLE: Active Storage redirect mode exposes direct cloud URLs that bypass
# application authorization. Once a user obtains the URL, they can share it with
# anyone — even unauthenticated users.
Rails.application.routes.draw do
  # Default Active Storage routes use redirect mode
  # GET /rails/active_storage/blobs/redirect/:signed_id/*filename
  # These signed URLs have a long default expiry and no auth check
end

# app/views/evidences/show.html.erb
# Direct link exposes a signed redirect URL
<%= link_to "Download Evidence", rails_blob_path(@evidence.file, disposition: "attachment") %>
```

**Secure Fix:**
```ruby
# config/routes.rb
# SECURE: Use proxy mode so every file request goes through the Rails app,
# where Pundit authorization is enforced
Rails.application.routes.draw do
  # Override Active Storage to use proxy mode
  resolve("ActiveStorage::Blob") { |blob| route_for(:rails_storage_proxy, blob) }
  resolve("ActiveStorage::Attachment") do |attachment|
    route_for(:rails_storage_proxy, attachment.blob)
  end
end

# app/controllers/evidences_controller.rb
# SECURE: Authorization is checked before the file is served via proxy
class EvidencesController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_authorized

  # @return [void]
  def show
    @evidence = Evidence.find(params[:id])
    authorize @evidence
  end
end

# app/policies/evidence_policy.rb
class EvidencePolicy < ApplicationPolicy
  # @return [Boolean] whether the user can view this evidence
  def show?
    sighting = record.sighting
    sighting.published? ||
      sighting.submitter_id == user.id ||
      assigned_investigator? ||
      user.admin?
  end

  private

  # @return [Boolean] whether the user is the assigned investigator
  def assigned_investigator?
    user.investigator? &&
      record.sighting.investigation&.investigator_id == user.id
  end
end
```

#### Example 5: Missing `policy_scope` in Index Action

**Source:** https://github.com/varvet/pundit#scopes
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/investigations_controller.rb
# VULNERABLE: No policy_scope — all investigations are returned regardless of
# the current user's role. Members can see investigator-only data.
class InvestigationsController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_authorized, except: :index
  # Missing: after_action :verify_policy_scoped, only: :index

  def index
    @investigations = Investigation.includes(:sighting, :investigator).all
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/investigations_controller.rb
# SECURE: policy_scope limits results; verify_policy_scoped enforces usage
class InvestigationsController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index

  # @return [void]
  def index
    @investigations = policy_scope(Investigation)
                        .includes(:sighting, :investigator)
                        .order(created_at: :desc)
                        .page(params[:page])
  end
end

# app/policies/investigation_policy.rb
class InvestigationPolicy < ApplicationPolicy
  class Scope < ApplicationPolicy::Scope
    # @return [ActiveRecord::Relation] scoped investigations based on role
    def resolve
      if user.admin?
        scope.all
      elsif user.investigator?
        scope.where(investigator: user)
      else
        scope.joins(:sighting).where(sightings: { submitter_id: user.id })
      end
    end
  end
end
```

#### Example 6: Membership Tier Bypass — Premium Feature Without Tier Check

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/policies/sighting_policy.rb
# VULNERABLE: bulk_export? only checks role, not membership tier.
# A member on the basic (free) tier can export data meant for premium users.
class SightingPolicy < ApplicationPolicy
  def bulk_export?
    user.member? || user.investigator? || user.admin?
  end
end
```

**Secure Fix:**
```ruby
# app/policies/sighting_policy.rb
# SECURE: Check both role AND membership tier. Premium features require
# an active membership at the premium or platinum tier.
class SightingPolicy < ApplicationPolicy
  # @return [Boolean] whether the user can perform bulk export
  def bulk_export?
    return true if user.admin?

    user.active_membership&.tier&.in?(%w[premium platinum])
  end

  # @return [Boolean] whether the user can use advanced spatial analysis
  def spatial_analysis?
    return true if user.admin?

    user.active_membership&.tier == "platinum"
  end
end

# app/models/user.rb (relevant method)
class User < ApplicationRecord
  has_many :memberships, dependent: :destroy

  # @return [Membership, nil] the current active membership
  def active_membership
    memberships.active.order(created_at: :desc).first
  end
end
```

#### Example 7: API Key Scope Escalation

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#api-keys
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/base_controller.rb
# VULNERABLE: API key authentication only checks existence, not scopes.
# A read-only API key can perform write operations.
class Api::V1::BaseController < ActionController::API
  include Pundit::Authorization
  before_action :authenticate_api_key!

  private

  def authenticate_api_key!
    key_value = request.headers["X-API-Key"]
    digest = Digest::SHA256.hexdigest(key_value.to_s)
    @current_api_key = ApiKey.find_by(key_digest: digest)
    head :unauthorized unless @current_api_key
  end
end

# app/controllers/api/v1/sightings_controller.rb
class Api::V1::SightingsController < Api::V1::BaseController
  def create
    # No scope check — read-only keys can create sightings
    @sighting = Sighting.new(sighting_params)
    authorize @sighting
    @sighting.save!
    render json: @sighting, status: :created
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/base_controller.rb
# SECURE: Authenticate API key, check active status, enforce scopes, and
# track usage against monthly quota.
class Api::V1::BaseController < ActionController::API
  include Pundit::Authorization
  before_action :authenticate_api_key!
  before_action :enforce_api_scope!
  before_action :enforce_monthly_quota!
  after_action :verify_authorized

  attr_reader :current_api_key

  private

  # @raise [ActionController::RoutingError] if API key is missing or invalid
  # @return [void]
  def authenticate_api_key!
    key_value = request.headers["X-API-Key"]
    return head(:unauthorized) if key_value.blank?

    digest = Digest::SHA256.hexdigest(key_value)
    @current_api_key = ApiKey.active.find_by(key_digest: digest)
    head(:unauthorized) unless @current_api_key
  end

  # @return [void]
  def enforce_api_scope!
    required_scope = write_action? ? "write" : "read"
    unless current_api_key.scopes.include?(required_scope)
      head :forbidden
    end
  end

  # @return [void]
  def enforce_monthly_quota!
    if current_api_key.monthly_requests_used >= current_api_key.monthly_request_limit
      head :too_many_requests
    else
      current_api_key.increment!(:monthly_requests_used)
    end
  end

  # @return [Boolean] whether the current action is a write operation
  def write_action?
    request.method.in?(%w[POST PUT PATCH DELETE])
  end
end
```

### Advanced Level

#### Example 8: `skip_authorization` Abuse Without Justification

**Source:** https://github.com/varvet/pundit#policy-and-scope-verification
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/stripe_webhooks_controller.rb
# VULNERABLE: skip_authorization with no justification permanently disables
# Pundit enforcement. An attacker who discovers this endpoint can forge
# webhook events to manipulate memberships.
class StripeWebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token
  skip_authorization # "Added during development, TODO remove"

  def create
    event = JSON.parse(request.body.read)
    # Processes webhook without verifying Stripe signature
    handle_event(event)
    head :ok
  end

  private

  def handle_event(event)
    case event["type"]
    when "customer.subscription.updated"
      # Trusts webhook payload directly — no re-fetch from Stripe API
      subscription = event.dig("data", "object")
      membership = Membership.find_by(stripe_subscription_id: subscription["id"])
      membership&.update!(tier: map_tier(subscription.dig("plan", "id")))
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/stripe_webhooks_controller.rb
# SECURE: Verify Stripe signature, store event IDs for idempotency,
# re-fetch from Stripe API, use pessimistic locking.
# skip_authorization is justified: webhook has no current_user context;
# authentication is via Stripe-Signature header verification.
class StripeWebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token
  # Justified: Stripe webhooks authenticate via Stripe-Signature header,
  # not via session/Pundit. No current_user exists in this context.
  skip_after_action :verify_authorized

  # @return [void]
  def create
    payload = request.body.read
    sig_header = request.headers["Stripe-Signature"]

    begin
      event = Stripe::Webhook.construct_event(
        payload, sig_header, Rails.application.credentials.stripe[:webhook_secret]
      )
    rescue JSON::ParserError, Stripe::SignatureVerificationError => e
      Rails.logger.warn("Stripe webhook rejected: #{e.class}")
      head :bad_request
      return
    end

    # Idempotency: skip already-processed events
    return head(:ok) if StripeWebhookEvent.exists?(stripe_event_id: event.id)

    StripeWebhookEvent.create!(stripe_event_id: event.id, event_type: event.type)
    ProcessStripeWebhookJob.perform_later(event.id, event.type)
    head :ok
  end
end

# app/jobs/process_stripe_webhook_job.rb
# SECURE: Re-fetches data from Stripe API; never trusts webhook payload.
class ProcessStripeWebhookJob < ApplicationJob
  queue_as :webhooks

  # @param stripe_event_id [String] the Stripe event ID
  # @param event_type [String] the Stripe event type
  # @return [void]
  def perform(stripe_event_id, event_type)
    event = Stripe::Event.retrieve(stripe_event_id)

    case event.type
    when "customer.subscription.updated"
      subscription = Stripe::Subscription.retrieve(event.data.object.id)
      Membership.transaction do
        membership = Membership.lock("FOR UPDATE")
                               .find_by!(stripe_subscription_id: subscription.id)
        membership.update!(
          tier: TierMapper.from_stripe_price(subscription.items.data.first.price.id),
          status: subscription.status
        )
      end
    end
  end
end
```

#### Example 9: Horizontal Privilege Escalation on Investigation Assignment

**Source:** CVE-2018-3760 (Sprockets path traversal — analogous pattern for IDOR in resource assignment)
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/investigations_controller.rb
# VULNERABLE: Any investigator can assign themselves to any sighting's
# investigation by sending investigator_id=<their_id> for any sighting.
# No check that the sighting was assigned to them by an admin.
class InvestigationsController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_authorized

  def create
    @investigation = Investigation.new(investigation_params)
    authorize @investigation
    @investigation.save!
    redirect_to @investigation
  end

  private

  def investigation_params
    params.require(:investigation).permit(:sighting_id, :investigator_id, :notes)
  end
end

# app/policies/investigation_policy.rb
class InvestigationPolicy < ApplicationPolicy
  def create?
    user.investigator? || user.admin?
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/investigations_controller.rb
# SECURE: Only admins can create investigations and assign investigators.
# investigator_id is not user-controllable for non-admins.
class InvestigationsController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_authorized

  # @return [void]
  def create
    @investigation = Investigation.new(investigation_params)
    authorize @investigation
    @investigation.save!
    AuditLog.create!(
      actor: current_user,
      action: "investigation_assigned",
      target: @investigation,
      metadata: {
        sighting_id: @investigation.sighting_id,
        investigator_id: @investigation.investigator_id
      }
    )
    redirect_to @investigation, notice: "Investigation created."
  end

  private

  # @return [ActionController::Parameters] permitted investigation attributes
  def investigation_params
    permitted = [:sighting_id, :notes]
    # Only admins can assign an investigator; non-admins cannot set investigator_id
    permitted << :investigator_id if current_user.admin?
    params.require(:investigation).permit(permitted)
  end
end

# app/policies/investigation_policy.rb
class InvestigationPolicy < ApplicationPolicy
  # @return [Boolean] whether the user can create an investigation
  def create?
    user.admin?
  end

  # @return [Boolean] whether the user can update the investigation
  def update?
    user.admin? || assigned_investigator?
  end

  private

  # @return [Boolean] whether the user is the assigned investigator
  def assigned_investigator?
    user.investigator? && record.investigator_id == user.id
  end
end
```

#### Example 10: Admin Panel Route Constraint Bypass

**Source:** https://guides.rubyonrails.org/routing.html#advanced-constraints
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/routes.rb
# VULNERABLE: Admin namespace has no routing constraint. The only protection
# is Pundit in individual controllers — if any admin controller forgets
# authorize, the route is wide open.
Rails.application.routes.draw do
  namespace :admin do
    resources :users
    resources :audit_logs, only: [:index, :show]
    resources :sightings
  end
end
```

**Secure Fix:**
```ruby
# config/routes.rb
# SECURE: Defense-in-depth — routing constraint checks admin role BEFORE
# the request reaches any controller. Pundit in controllers is the second layer.
Rails.application.routes.draw do
  namespace :admin, constraints: AdminConstraint.new do
    resources :users
    resources :audit_logs, only: [:index, :show]
    resources :sightings
  end
end

# app/constraints/admin_constraint.rb
# SECURE: Routing constraint that rejects non-admin users at the routing layer.
# This is defense-in-depth; Pundit policies are still enforced in controllers.
class AdminConstraint
  # @param request [ActionDispatch::Request] the incoming HTTP request
  # @return [Boolean] whether the request should be routed to admin namespace
  def matches?(request)
    user = current_user(request)
    user.present? && user.admin?
  end

  private

  # @param request [ActionDispatch::Request] the incoming HTTP request
  # @return [User, nil] the authenticated user from the session
  def current_user(request)
    User.find_by(id: request.session[:user_id])
  rescue ActiveRecord::RecordNotFound
    nil
  end
end
```

#### Example 11: API Serializer PII Over-Exposure Without Role Gating
**Source:** Phase 1i security review — discovered in APRS codebase (2026-02-09)
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/serializers/api/v1/sighting_serializer.rb
# VULNERABLE: Unconditionally exposes submitter email to ALL API consumers,
# regardless of role. Any member can harvest all submitter emails by
# paginating through GET /api/v1/sightings. The web views deliberately
# omit this field, making the API inconsistent with the web's PII posture.
# Witness contact_info is correctly gated, but submitter email is not.
class Api::V1::SightingSerializer
  def initialize(sighting)
    @sighting = sighting
  end

  def as_json
    {
      id: @sighting.id,
      description: @sighting.description,
      submitter_email: @sighting.submitter&.email,  # PII leak!
      # ... other fields
    }
  end
end
```

**Secure Fix:**
```ruby
# app/serializers/api/v1/sighting_serializer.rb
# SECURE: Remove PII fields that are not needed by all API consumers.
# If certain roles (investigator/admin) need submitter identity, gate it
# behind a policy check, consistent with how WitnessPolicy#show_contact_info?
# gates witness PII. When in doubt, match what the web views expose.
class Api::V1::SightingSerializer
  def initialize(sighting)
    @sighting = sighting
  end

  def as_json
    {
      id: @sighting.id,
      description: @sighting.description,
      # submitter_email intentionally excluded — PII not needed by all consumers
      # ... other fields
    }
  end
end
```

## Checklist

- [ ] Every controller action calls `authorize @record` (or `authorize :<model>` for collection actions)
- [ ] `after_action :verify_authorized, except: :index` is present in `ApplicationController` or every controller
- [ ] `after_action :verify_policy_scoped, only: :index` is present in `ApplicationController` or every controller
- [ ] No `skip_authorization` without an inline comment documenting the justification
- [ ] No `skip_after_action :verify_authorized` without an inline comment documenting the justification
- [ ] Pundit policies check `record.submitter_id == user.id` for ownership-gated actions
- [ ] Pundit policies check both `user.role` AND `user.active_membership&.tier` for tier-gated features
- [ ] Strong parameters never include `role`, `admin`, `membership_tier`, or other privilege-escalation fields
- [ ] Active Storage uses proxy mode (not redirect mode) so authorization is enforced on every file access
- [ ] API key authentication verifies key existence, active status, scope, and monthly quota
- [ ] Admin routes are protected by both a routing constraint AND Pundit policies (defense-in-depth)
- [ ] Index actions use `policy_scope(Model)` instead of `Model.all`
- [ ] Investigation assignment is admin-only; investigators cannot self-assign
- [ ] Stripe webhook endpoints verify `Stripe-Signature` and use `skip_after_action :verify_authorized` (not `skip_authorization`) with documented justification
- [ ] All role/tier changes are recorded in `AuditLog`
- [ ] No controller uses `params.permit!` (permit-all)
- [ ] API serializers do not expose PII (email, name, contact_info, coordinates) without role-based gating — cross-check against what web views expose
- [ ] Every PII field in a serializer is gated behind a policy check (e.g., `WitnessPolicy#show_contact_info?`) or excluded entirely
