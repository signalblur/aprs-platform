# frozen_string_literal: true

# Creates the environmental_traces table for tracking physical traces
# or environmental changes observed at UAP sighting locations.
# Includes optional PostGIS geography point for precise trace location.
class CreateEnvironmentalTraces < ActiveRecord::Migration[8.1]
  def change
    create_table :environmental_traces do |t|
      t.references :sighting, null: false, foreign_key: true, index: true
      t.string :trace_type, null: false
      t.text :description
      t.st_point :location, geographic: true, srid: 4326
      t.string :measured_value
      t.string :measurement_unit
      t.timestamps
    end

    add_index :environmental_traces, :location, using: :gist
  end
end
