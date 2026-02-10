# frozen_string_literal: true

# Tracks malfunctions or interference with electronic/mechanical equipment during a UAP sighting.
#
# Records what equipment was affected and how it malfunctioned. Useful for
# detecting patterns (e.g., multiple vehicle stalls at the same location).
#
# @attr [Sighting] sighting the parent sighting report
# @attr [String] equipment_type the type of equipment affected (e.g., "car_engine", "radio")
# @attr [String] effect_type how the equipment was affected (e.g., "malfunction", "shutdown")
# @attr [String, nil] description detailed description of the equipment effect
class EquipmentEffect < ApplicationRecord
  belongs_to :sighting

  validates :equipment_type, presence: true
  validates :effect_type, presence: true
end
