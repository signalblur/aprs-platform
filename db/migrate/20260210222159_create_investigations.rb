# frozen_string_literal: true

class CreateInvestigations < ActiveRecord::Migration[8.1]
  def change
    create_table :investigations do |t|
      t.string :case_number, null: false
      t.string :title, null: false
      t.text :description
      t.integer :status, null: false, default: 0
      t.integer :priority, null: false, default: 0
      t.integer :classification
      t.text :findings
      t.references :assigned_investigator, foreign_key: { to_table: :users }, index: true
      t.column :opened_at, :timestamptz, null: false
      t.column :closed_at, :timestamptz

      t.timestamps
    end

    add_index :investigations, :case_number, unique: true
    add_index :investigations, :status
    add_index :investigations, :priority
  end
end
