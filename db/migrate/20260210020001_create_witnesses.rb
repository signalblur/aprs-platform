# frozen_string_literal: true

# Creates the witnesses table for observer records linked to sightings.
# contact_info is encrypted at the application layer via Active Record Encryption.
class CreateWitnesses < ActiveRecord::Migration[8.1]
  def change
    create_table :witnesses do |t|
      t.references :sighting, null: false, foreign_key: true, index: true
      t.string :name
      t.string :contact_info
      t.text :statement
      t.text :credibility_notes
      t.timestamps
    end
  end
end
