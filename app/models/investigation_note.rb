# frozen_string_literal: true

# Timestamped notes on an investigation, authored by investigators or admins.
#
# Supports different note types to categorize entries in the investigation
# timeline: general observations, status changes, assignment updates, and findings.
#
# @attr [Investigation] investigation the parent investigation
# @attr [User] author the user who wrote the note
# @attr [String] content the note content (1-10,000 chars)
# @attr [Integer] note_type the category of note (general, status_change, assignment, finding)
class InvestigationNote < ApplicationRecord
  belongs_to :investigation
  belongs_to :author, class_name: "User", inverse_of: :investigation_notes

  enum :note_type, {
    general: 0,
    status_change: 1,
    assignment: 2,
    finding: 3
  }, default: :general, validate: true

  validates :content, presence: true, length: { minimum: 1, maximum: 10_000 }
end
