# frozen_string_literal: true

class CreateInvestigationNotes < ActiveRecord::Migration[8.1]
  def change
    create_table :investigation_notes do |t|
      t.references :investigation, null: false, foreign_key: true, index: true
      t.references :author, null: false, foreign_key: { to_table: :users }, index: true
      t.text :content, null: false
      t.integer :note_type, null: false, default: 0

      t.timestamps
    end
  end
end
