# frozen_string_literal: true

# Creates the sightings table with PostGIS geography location,
# timestamptz for observed_at, and status workflow enum.
class CreateSightings < ActiveRecord::Migration[8.1]
  def change
    create_table :sightings do |t|
      t.references :submitter, null: true, foreign_key: { to_table: :users }, index: true
      t.references :shape, null: false, foreign_key: true, index: true
      t.text :description, null: false
      t.integer :duration_seconds
      t.st_point :location, geographic: true, srid: 4326
      t.decimal :altitude_feet
      t.column :observed_at, :timestamptz, null: false
      t.string :observed_timezone, null: false
      t.integer :num_witnesses, null: false, default: 1
      t.string :visibility_conditions
      t.text :weather_notes
      t.string :media_source
      t.integer :status, null: false, default: 0
      t.timestamps
    end

    add_index :sightings, :observed_at
    add_index :sightings, :status
    add_index :sightings, :location, using: :gist
  end
end
