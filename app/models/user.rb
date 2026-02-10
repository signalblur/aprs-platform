# frozen_string_literal: true

# User model for authentication and authorization.
#
# Manages user accounts with Devise authentication, role-based access
# control via Pundit, and account security features including lockout,
# email confirmation, and sign-in tracking.
#
# @attr [String] email the user's email address (unique, case-insensitive)
# @attr [Integer] role the user's access level (member, investigator, admin)
# @attr [Integer] sign_in_count total number of successful sign-ins
# @attr [Integer] failed_attempts consecutive failed sign-in attempts
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :trackable, :lockable, :confirmable

  has_many :sightings, foreign_key: :submitter_id, dependent: :restrict_with_error, inverse_of: :submitter

  enum :role, { member: 0, investigator: 1, admin: 2 }, default: :member, validate: true
end
