# frozen_string_literal: true

# Creates the physiological_effects table for tracking physical effects
# reported by witnesses during or after UAP sightings.
class CreatePhysiologicalEffects < ActiveRecord::Migration[8.1]
  def change
    create_table :physiological_effects do |t|
      t.references :sighting, null: false, foreign_key: true, index: true
      t.string :effect_type, null: false
      t.text :description
      t.integer :severity, null: false, default: 0
      t.string :onset
      t.string :duration
      t.timestamps
    end
  end
end
