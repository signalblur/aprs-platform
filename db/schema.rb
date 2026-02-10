# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_02_10_031157) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "fuzzystrmatch"
  enable_extension "pg_catalog.plpgsql"
  enable_extension "postgis"

  create_table "active_storage_attachments", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.bigint "record_id", null: false
    t.string "record_type", null: false
    t.index ["blob_id"], name: "index_active_storage_attachments_on_blob_id"
    t.index ["record_type", "record_id", "name", "blob_id"], name: "index_active_storage_attachments_uniqueness", unique: true
  end

  create_table "active_storage_blobs", force: :cascade do |t|
    t.bigint "byte_size", null: false
    t.string "checksum"
    t.string "content_type"
    t.datetime "created_at", null: false
    t.string "filename", null: false
    t.string "key", null: false
    t.text "metadata"
    t.string "service_name", null: false
    t.index ["key"], name: "index_active_storage_blobs_on_key", unique: true
  end

  create_table "active_storage_variant_records", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.string "variation_digest", null: false
    t.index ["blob_id", "variation_digest"], name: "index_active_storage_variant_records_uniqueness", unique: true
  end

  create_table "api_keys", force: :cascade do |t|
    t.boolean "active", default: true, null: false
    t.datetime "created_at", null: false
    t.datetime "expires_at"
    t.string "key_digest", null: false
    t.string "key_prefix", limit: 8, null: false
    t.datetime "last_used_at"
    t.string "name", null: false
    t.datetime "updated_at", null: false
    t.bigint "user_id", null: false
    t.index ["key_digest"], name: "index_api_keys_on_key_digest", unique: true
    t.index ["user_id"], name: "index_api_keys_on_user_id"
  end

  create_table "environmental_traces", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "description"
    t.geography "location", limit: {srid: 4326, type: "st_point", geographic: true}
    t.string "measured_value"
    t.string "measurement_unit"
    t.bigint "sighting_id", null: false
    t.string "trace_type", null: false
    t.datetime "updated_at", null: false
    t.index ["location"], name: "index_environmental_traces_on_location", using: :gist
    t.index ["sighting_id"], name: "index_environmental_traces_on_sighting_id"
  end

  create_table "equipment_effects", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "description"
    t.string "effect_type", null: false
    t.string "equipment_type", null: false
    t.bigint "sighting_id", null: false
    t.datetime "updated_at", null: false
    t.index ["sighting_id"], name: "index_equipment_effects_on_sighting_id"
  end

  create_table "evidences", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "description"
    t.integer "evidence_type", default: 0, null: false
    t.bigint "sighting_id", null: false
    t.bigint "submitted_by_id", null: false
    t.datetime "updated_at", null: false
    t.index ["sighting_id"], name: "index_evidences_on_sighting_id"
    t.index ["submitted_by_id"], name: "index_evidences_on_submitted_by_id"
  end

  create_table "physiological_effects", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "description"
    t.string "duration"
    t.string "effect_type", null: false
    t.string "onset"
    t.integer "severity", default: 0, null: false
    t.bigint "sighting_id", null: false
    t.datetime "updated_at", null: false
    t.index ["sighting_id"], name: "index_physiological_effects_on_sighting_id"
  end

  create_table "psychological_effects", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "description"
    t.string "duration"
    t.string "effect_type", null: false
    t.string "onset"
    t.integer "severity", default: 0, null: false
    t.bigint "sighting_id", null: false
    t.datetime "updated_at", null: false
    t.index ["sighting_id"], name: "index_psychological_effects_on_sighting_id"
  end

  create_table "shapes", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "description"
    t.string "name", null: false
    t.datetime "updated_at", null: false
    t.index ["name"], name: "index_shapes_on_name", unique: true
  end

  create_table "sightings", force: :cascade do |t|
    t.decimal "altitude_feet"
    t.datetime "created_at", null: false
    t.text "description", null: false
    t.integer "duration_seconds"
    t.geography "location", limit: {srid: 4326, type: "st_point", geographic: true}
    t.string "media_source"
    t.integer "num_witnesses", default: 1, null: false
    t.timestamptz "observed_at", null: false
    t.string "observed_timezone", null: false
    t.bigint "shape_id", null: false
    t.integer "status", default: 0, null: false
    t.bigint "submitter_id"
    t.datetime "updated_at", null: false
    t.string "visibility_conditions"
    t.text "weather_notes"
    t.index ["location"], name: "index_sightings_on_location", using: :gist
    t.index ["observed_at"], name: "index_sightings_on_observed_at"
    t.index ["shape_id"], name: "index_sightings_on_shape_id"
    t.index ["status"], name: "index_sightings_on_status"
    t.index ["submitter_id"], name: "index_sightings_on_submitter_id"
  end

  create_table "users", force: :cascade do |t|
    t.datetime "confirmation_sent_at"
    t.string "confirmation_token"
    t.datetime "confirmed_at"
    t.datetime "created_at", null: false
    t.datetime "current_sign_in_at"
    t.string "current_sign_in_ip"
    t.string "email", default: "", null: false
    t.string "encrypted_password", default: "", null: false
    t.integer "failed_attempts", default: 0, null: false
    t.datetime "last_sign_in_at"
    t.string "last_sign_in_ip"
    t.datetime "locked_at"
    t.datetime "remember_created_at"
    t.datetime "reset_password_sent_at"
    t.string "reset_password_token"
    t.integer "role", default: 0, null: false
    t.integer "sign_in_count", default: 0, null: false
    t.string "unconfirmed_email"
    t.string "unlock_token"
    t.datetime "updated_at", null: false
    t.index ["confirmation_token"], name: "index_users_on_confirmation_token", unique: true
    t.index ["email"], name: "index_users_on_email", unique: true
    t.index ["reset_password_token"], name: "index_users_on_reset_password_token", unique: true
    t.index ["role"], name: "index_users_on_role"
    t.index ["unlock_token"], name: "index_users_on_unlock_token", unique: true
  end

  create_table "witnesses", force: :cascade do |t|
    t.string "contact_info"
    t.datetime "created_at", null: false
    t.text "credibility_notes"
    t.string "name"
    t.bigint "sighting_id", null: false
    t.text "statement"
    t.datetime "updated_at", null: false
    t.index ["sighting_id"], name: "index_witnesses_on_sighting_id"
  end

  add_foreign_key "active_storage_attachments", "active_storage_blobs", column: "blob_id"
  add_foreign_key "active_storage_variant_records", "active_storage_blobs", column: "blob_id"
  add_foreign_key "api_keys", "users"
  add_foreign_key "environmental_traces", "sightings"
  add_foreign_key "equipment_effects", "sightings"
  add_foreign_key "evidences", "sightings"
  add_foreign_key "evidences", "users", column: "submitted_by_id"
  add_foreign_key "physiological_effects", "sightings"
  add_foreign_key "psychological_effects", "sightings"
  add_foreign_key "sightings", "shapes"
  add_foreign_key "sightings", "users", column: "submitter_id"
  add_foreign_key "witnesses", "sightings"
end
