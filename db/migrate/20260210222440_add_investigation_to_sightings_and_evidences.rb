# frozen_string_literal: true

class AddInvestigationToSightingsAndEvidences < ActiveRecord::Migration[8.1]
  def change
    # Add optional investigation FK to sightings
    add_reference :sightings, :investigation, foreign_key: true, index: true, null: true

    # Add optional investigation FK to evidences
    add_reference :evidences, :investigation, foreign_key: true, index: true, null: true

    # Make sighting_id nullable on evidences (was NOT NULL)
    change_column_null :evidences, :sighting_id, true

    # M19: Evidence XOR constraint — evidence belongs to either sighting OR investigation, not both
    reversible do |dir|
      dir.up do
        execute <<~SQL
          ALTER TABLE evidences
            ADD CONSTRAINT evidence_parent_xor
            CHECK (
              (sighting_id IS NOT NULL AND investigation_id IS NULL)
              OR
              (sighting_id IS NULL AND investigation_id IS NOT NULL)
            )
        SQL
      end

      dir.down do
        execute <<~SQL
          ALTER TABLE evidences DROP CONSTRAINT IF EXISTS evidence_parent_xor
        SQL
      end
    end
  end
end
