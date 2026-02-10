# frozen_string_literal: true

# Creates the evidences table for file-based evidence attached to sightings.
# Actual files are stored via Active Storage (separate blobs/attachments tables).
class CreateEvidences < ActiveRecord::Migration[8.1]
  def change
    create_table :evidences do |t|
      t.references :sighting, null: false, foreign_key: true, index: true
      t.references :submitted_by, null: false, foreign_key: { to_table: :users }, index: true
      t.integer :evidence_type, null: false, default: 0
      t.text :description
      t.timestamps
    end
  end
end
