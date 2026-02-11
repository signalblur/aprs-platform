# frozen_string_literal: true

module Api
  module V1
    # Serializes the current user's membership with tier and limits.
    #
    # If the user has no active membership, returns free tier defaults.
    class MembershipSerializer
      # @param user [User] the user whose membership to serialize
      def initialize(user)
        @user = user
        @membership = user.active_membership
      end

      # @return [Hash] JSON-compatible hash representation
      def as_json
        {
          tier: @user.tier,
          active: @membership&.usable? || false,
          starts_at: @membership&.starts_at&.iso8601,
          expires_at: @membership&.expires_at&.iso8601,
          limits: {
            sightings_per_month: @user.tier_limit(:sightings_per_month),
            evidence_per_sighting: @user.tier_limit(:evidence_per_sighting),
            evidence_max_size_mb: @user.tier_limit(:evidence_max_size_mb),
            api_keys: @user.tier_limit(:api_keys)
          }
        }
      end
    end
  end
end
