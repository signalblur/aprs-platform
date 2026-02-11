# frozen_string_literal: true

# Tracks admin-assigned membership tiers for users.
#
# Memberships are orthogonal to roles: roles control what actions a user can
# take (member/investigator/admin), while tiers control volume and feature
# depth (free/professional/organization). No membership record = free tier.
#
# @attr [Integer] tier the membership tier (free, professional, organization)
# @attr [String] notes admin justification for the assignment
# @attr [Boolean] active whether this membership is currently active
# @attr [Time] starts_at when the membership becomes effective
# @attr [Time] expires_at when the membership expires (nil = never)
class Membership < ApplicationRecord
  belongs_to :user
  belongs_to :granted_by, class_name: "User", optional: true

  enum :tier, { free: 0, professional: 1, organization: 2 }, default: :free, validate: true

  validates :starts_at, presence: true
  validate :one_active_per_user, on: :create

  scope :active, -> { where(active: true) }
  scope :current, -> { active.where("expires_at IS NULL OR expires_at > ?", Time.current) }

  # Checks if this membership has expired.
  #
  # @return [Boolean] true if expires_at is set and in the past
  def expired?
    expires_at.present? && expires_at <= Time.current
  end

  # Checks if this membership is usable (active and not expired).
  #
  # @return [Boolean] true if active and not expired
  def usable?
    active? && !expired?
  end

  private

  # Validates that only one active membership exists per user.
  #
  # The partial unique index enforces this at the DB level, but this
  # provides a friendlier error message at the model level.
  #
  # @return [void]
  def one_active_per_user
    return unless active?
    return unless user_id.present?
    return unless Membership.where(user_id: user_id, active: true).exists?

    errors.add(:user, "already has an active membership")
  end
end
