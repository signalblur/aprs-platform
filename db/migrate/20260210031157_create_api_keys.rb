# frozen_string_literal: true

class CreateApiKeys < ActiveRecord::Migration[8.1]
  def change
    create_table :api_keys do |t|
      t.references :user, null: false, foreign_key: true
      t.string :key_digest, null: false
      t.string :key_prefix, limit: 8, null: false
      t.string :name, null: false
      t.boolean :active, null: false, default: true
      t.datetime :last_used_at
      t.datetime :expires_at

      t.timestamps
    end

    add_index :api_keys, :key_digest, unique: true
  end
end
