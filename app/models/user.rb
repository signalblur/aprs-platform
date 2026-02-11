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
  has_many :evidences, foreign_key: :submitted_by_id, dependent: :restrict_with_error, inverse_of: :submitted_by
  has_many :api_keys, dependent: :destroy
  has_many :assigned_investigations, class_name: "Investigation", foreign_key: :assigned_investigator_id,
                                     dependent: :nullify, inverse_of: :assigned_investigator
  has_many :investigation_notes, foreign_key: :author_id, dependent: :restrict_with_error,
                                 inverse_of: :author

  enum :role, { member: 0, investigator: 1, admin: 2 }, default: :member, validate: true
end
