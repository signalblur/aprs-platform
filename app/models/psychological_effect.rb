# frozen_string_literal: true

# Tracks psychological/cognitive effects reported by witnesses during or after a UAP sighting.
#
# Records the type, severity, onset timing, and duration of psychological effects
# such as time loss, anxiety, compulsions, or vivid dreams experienced by observers.
#
# @attr [Sighting] sighting the parent sighting report
# @attr [String] effect_type the category of psychological effect (e.g., "time_loss", "anxiety")
# @attr [String, nil] description detailed description of the effect
# @attr [Integer] severity severity level (mild, moderate, severe)
# @attr [String, nil] onset when the effect started relative to the sighting
# @attr [String, nil] duration how long the effect lasted
class PsychologicalEffect < ApplicationRecord
  belongs_to :sighting

  enum :severity, { mild: 0, moderate: 1, severe: 2 }, default: :mild, validate: true

  validates :effect_type, presence: true
end
