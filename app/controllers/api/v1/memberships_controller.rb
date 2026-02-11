# frozen_string_literal: true

module Api
  module V1
    # Returns the current user's membership tier and limits.
    #
    # Always returns data — if no active membership exists, returns
    # free tier defaults with limits.
    class MembershipsController < BaseController
      skip_after_action :verify_policy_scoped
      skip_after_action :verify_authorized
      after_action :verify_authorized, only: :show

      # GET /api/v1/membership
      #
      # @return [void]
      def show
        membership = current_user.active_membership || Membership.new(user: current_user)
        authorize membership, policy_class: MembershipPolicy
        serializer = MembershipSerializer.new(current_user)
        render json: { data: serializer.as_json }
      end
    end
  end
end
