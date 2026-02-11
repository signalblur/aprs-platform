# frozen_string_literal: true

# Base controller for all web controllers.
#
# Enforces authentication via Devise and authorization via Pundit on every
# action. Devise controllers are excluded because they handle their own
# authentication flow (sign in, sign up, password reset, etc.).
class ApplicationController < ActionController::Base
  include Pundit::Authorization
  include Pagy::Backend

  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  # Changes to the importmap will invalidate the etag for HTML responses
  stale_when_importmap_changes

  before_action :authenticate_user!, unless: :devise_controller?

  # Use conditional procs instead of :only/:except to avoid
  # raise_on_missing_callback_actions failures on Devise controllers
  # (which don't define index and would fail the action existence check).
  after_action :verify_authorized, unless: -> { devise_controller? || action_name == "index" }
  after_action :verify_policy_scoped, if: -> { !devise_controller? && action_name == "index" }

  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized

  private

  # Handles unauthorized access attempts by redirecting with an alert.
  #
  # @param _exception [Pundit::NotAuthorizedError] the authorization error
  # @return [void]
  def user_not_authorized(_exception)
    flash[:alert] = "You are not authorized to perform this action."
    redirect_back(fallback_location: root_path)
  end
end
