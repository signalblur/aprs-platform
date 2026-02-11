# frozen_string_literal: true

# Creates the memberships table for admin-assigned tier management.
#
# Memberships track which tier (free/professional/organization) a user
# has been assigned by an admin, with audit trail (granted_by, notes).
# A partial unique index ensures at most one active membership per user.
class CreateMemberships < ActiveRecord::Migration[8.1]
  def change
    create_table :memberships do |t|
      t.references :user, null: false, foreign_key: true
      t.integer :tier, null: false, default: 0
      t.references :granted_by, null: true, foreign_key: { to_table: :users }
      t.text :notes
      t.column :starts_at, :timestamptz, null: false
      t.column :expires_at, :timestamptz
      t.boolean :active, null: false, default: true

      t.timestamps
    end

    add_index :memberships, %i[user_id active]
    add_index :memberships, :user_id, unique: true, where: "active = true",
              name: "index_memberships_one_active_per_user"
  end
end
