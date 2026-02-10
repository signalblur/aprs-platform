# frozen_string_literal: true

# Creates the psychological_effects table for tracking cognitive/psychological
# effects reported by witnesses during or after UAP sightings.
class CreatePsychologicalEffects < ActiveRecord::Migration[8.1]
  def change
    create_table :psychological_effects do |t|
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
