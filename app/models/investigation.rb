# frozen_string_literal: true

# Investigation case management for grouping related UAP sightings.
#
# Tracks investigation progress from open to closed, records findings
# and classification outcomes, and links related sightings. Case numbers
# are auto-generated in the format APRS-YYYYMMDD-XXXX.
#
# @attr [String] case_number unique auto-generated case identifier
# @attr [String] title investigation title (5-200 chars)
# @attr [String, nil] description optional investigation description
# @attr [Integer] status workflow status (open, in_progress, closed_resolved, closed_unresolved, closed_inconclusive)
# @attr [Integer] priority case priority (low, medium, high, critical)
# @attr [Integer, nil] classification outcome classification (identified, unidentified, insufficient_data, hoax)
# @attr [String, nil] findings final investigation report text
# @attr [User, nil] assigned_investigator the investigator assigned to this case
# @attr [Time] opened_at when the investigation was opened
# @attr [Time, nil] closed_at when the investigation was closed
class Investigation < ApplicationRecord
  belongs_to :assigned_investigator, class_name: "User", optional: true, inverse_of: :assigned_investigations
  has_many :sightings, dependent: :nullify
  has_many :investigation_notes, dependent: :destroy
  has_many :evidences, dependent: :restrict_with_error

  enum :status, {
    open: 0,
    in_progress: 1,
    closed_resolved: 2,
    closed_unresolved: 3,
    closed_inconclusive: 4
  }, default: :open, validate: true

  enum :priority, {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3
  }, default: :low, validate: true, prefix: true

  enum :classification, {
    identified: 0,
    unidentified: 1,
    insufficient_data: 2,
    hoax: 3
  }, prefix: true, validate: { allow_nil: true }

  validates :case_number, presence: true, uniqueness: true
  validates :title, presence: true, length: { minimum: 5, maximum: 200 }
  validates :opened_at, presence: true
  validate :closed_at_required_when_closed
  validate :classification_required_when_closed
  validate :assigned_investigator_must_have_role

  before_validation :generate_case_number, on: :create

  # Orders investigations by most recently opened first.
  #
  # @return [ActiveRecord::Relation]
  scope :recent, -> { order(opened_at: :desc) }

  # Filters investigations by workflow status.
  #
  # @param status [Symbol, String, Integer]
  # @return [ActiveRecord::Relation]
  scope :by_status, ->(status) { where(status: status) }

  # Filters investigations by priority level.
  #
  # @param priority [Symbol, String, Integer]
  # @return [ActiveRecord::Relation]
  scope :by_priority, ->(priority) { where(priority: priority) }

  # Filters investigations assigned to a specific user.
  #
  # @param user [User]
  # @return [ActiveRecord::Relation]
  scope :assigned_to, ->(user) { where(assigned_investigator: user) }

  # Returns investigations that are not closed.
  #
  # @return [ActiveRecord::Relation]
  scope :open_cases, -> { where(status: %i[open in_progress]) }

  # Checks whether the investigation has a closed status.
  #
  # @return [Boolean]
  def closed?
    closed_resolved? || closed_unresolved? || closed_inconclusive?
  end

  private

  # Generates a unique case number in the format APRS-YYYYMMDD-XXXX.
  # Uses a date-scoped counter with retry on uniqueness collision.
  #
  # @return [void]
  def generate_case_number
    return if case_number.present?

    date_prefix = "APRS-#{Time.current.strftime('%Y%m%d')}"
    max_attempts = 10

    max_attempts.times do
      today_count = Investigation.where("case_number LIKE ?", "#{date_prefix}%").count
      candidate = format("%s-%04d", date_prefix, today_count + 1)

      unless Investigation.exists?(case_number: candidate)
        self.case_number = candidate
        return
      end
    end

    # Fallback: use SecureRandom for uniqueness
    self.case_number = format("%s-%s", date_prefix, SecureRandom.hex(4).upcase)
  end

  # Validates that closed_at is present when status is a closed variant.
  #
  # @return [void]
  def closed_at_required_when_closed
    return unless closed?
    return if closed_at.present?

    errors.add(:closed_at, "is required when investigation is closed")
  end

  # Validates that classification is present when status is a closed variant.
  #
  # @return [void]
  def classification_required_when_closed
    return unless closed?
    return if classification.present?

    errors.add(:classification, "is required when investigation is closed")
  end

  # Validates that assigned_investigator has investigator or admin role.
  #
  # @return [void]
  def assigned_investigator_must_have_role
    return unless assigned_investigator.present?
    return if assigned_investigator.investigator? || assigned_investigator.admin?

    errors.add(:assigned_investigator, "must be an investigator or admin")
  end
end
