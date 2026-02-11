# frozen_string_literal: true

# Provides tier-based limit checking for users.
#
# Tiers are orthogonal to roles: roles control what actions a user can take,
# while tiers control volume and feature depth. No active membership = free tier.
#
# @example Check if a user is within their sighting submission limit
#   user.within_tier_limit?(:sightings_per_month, user.sightings.where(...).count)
module TierLimits
  extend ActiveSupport::Concern

  LIMITS = {
    free: {
      sightings_per_month: 5,
      evidence_per_sighting: 3,
      evidence_max_size_mb: 50,
      api_keys: 1
    },
    professional: {
      sightings_per_month: 50,
      evidence_per_sighting: 10,
      evidence_max_size_mb: 100,
      api_keys: 5
    },
    organization: {
      sightings_per_month: nil,
      evidence_per_sighting: 20,
      evidence_max_size_mb: 100,
      api_keys: 20
    }
  }.freeze

  # Returns the user's current tier name.
  #
  # @return [String] the tier name ("free", "professional", or "organization")
  def tier
    active_membership&.usable? ? active_membership.tier : "free"
  end

  # Returns whether the user has professional tier or above.
  #
  # @return [Boolean]
  def professional_or_above?
    %w[professional organization].include?(tier)
  end

  # Returns whether the user has organization tier.
  #
  # @return [Boolean]
  def organization?
    tier == "organization"
  end

  # Returns the limit value for the given limit name based on the user's tier.
  #
  # @param limit_name [Symbol] the limit key (e.g., :sightings_per_month)
  # @return [Integer, nil] the limit value, or nil for unlimited
  def tier_limit(limit_name)
    LIMITS.fetch(tier.to_sym).fetch(limit_name)
  end

  # Checks if the current count is within the user's tier limit.
  #
  # Admins bypass all tier limits. A nil limit means unlimited.
  #
  # @param limit_name [Symbol] the limit key
  # @param current_count [Integer] the current usage count
  # @return [Boolean] true if within limit or unlimited
  def within_tier_limit?(limit_name, current_count)
    return true if admin?

    limit = tier_limit(limit_name)
    return true if limit.nil?

    current_count < limit
  end
end
