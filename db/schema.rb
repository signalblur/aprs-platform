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

ActiveRecord::Schema[8.1].define(version: 2026_02_10_001929) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "fuzzystrmatch"
  enable_extension "pg_catalog.plpgsql"
  enable_extension "postgis"

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

  add_foreign_key "environmental_traces", "sightings"
  add_foreign_key "equipment_effects", "sightings"
  add_foreign_key "physiological_effects", "sightings"
  add_foreign_key "psychological_effects", "sightings"
  add_foreign_key "sightings", "shapes"
  add_foreign_key "sightings", "users", column: "submitter_id"
end
