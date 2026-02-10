# frozen_string_literal: true

module Api
  module V1
    # Base controller for API v1 endpoints.
    #
    # Inherits from ActionController::API (no CSRF, no sessions, no views)
    # to maintain a separate trust boundary from the web application.
    # Authenticates via SHA256-digested API key in the X-Api-Key header.
    class BaseController < ActionController::API
      include Pundit::Authorization
      include Pagy::Backend

      before_action :authenticate_api_key!
      after_action :verify_authorized, except: :index
      after_action :verify_policy_scoped, only: :index

      rescue_from Pundit::NotAuthorizedError, with: :render_forbidden
      rescue_from ActiveRecord::RecordNotFound, with: :render_not_found
      rescue_from Pagy::OverflowError, with: :render_not_found

      attr_reader :current_user

      private

      # Authenticates the request via the X-Api-Key header.
      #
      # Looks up the API key by SHA256 digest and verifies it is usable
      # (active and not expired). Sets current_user from the key owner.
      #
      # @return [void]
      def authenticate_api_key!
        raw_key = request.headers["X-Api-Key"]
        @current_api_key = ApiKey.find_by_raw_key(raw_key)

        if @current_api_key&.usable?
          @current_user = @current_api_key.user
          @current_api_key.touch_last_used!
        else
          render json: { error: "Unauthorized" }, status: :unauthorized
        end
      end

      # Renders a 403 Forbidden JSON response.
      #
      # @param _exception [Pundit::NotAuthorizedError]
      # @return [void]
      def render_forbidden(_exception)
        render json: { error: "Forbidden" }, status: :forbidden
      end

      # Renders a 404 Not Found JSON response.
      #
      # @param _exception [ActiveRecord::RecordNotFound, Pagy::OverflowError]
      # @return [void]
      def render_not_found(_exception)
        render json: { error: "Not found" }, status: :not_found
      end

      # Builds pagination metadata from a Pagy instance.
      #
      # @param pagy [Pagy] the pagination object
      # @return [Hash] pagination metadata
      def pagination_meta(pagy)
        {
          page: pagy.page,
          per_page: pagy.limit,
          total: pagy.count,
          total_pages: pagy.pages
        }
      end
    end
  end
end
