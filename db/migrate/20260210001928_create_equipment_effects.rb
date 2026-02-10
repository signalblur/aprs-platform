# frozen_string_literal: true

# Creates the equipment_effects table for tracking electronic/mechanical
# equipment malfunctions during UAP sightings.
class CreateEquipmentEffects < ActiveRecord::Migration[8.1]
  def change
    create_table :equipment_effects do |t|
      t.references :sighting, null: false, foreign_key: true, index: true
      t.string :equipment_type, null: false
      t.string :effect_type, null: false
      t.text :description
      t.timestamps
    end
  end
end
