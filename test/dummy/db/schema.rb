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

ActiveRecord::Schema[8.0].define(version: 2026_09_11_000001) do
  create_table "beskar_administrative_actions", force: :cascade do |t|
    t.string "actor", limit: 200, null: false
    t.string "action", null: false
    t.bigint "target_id", null: false
    t.string "operation_id", limit: 36, null: false
    t.string "request_id", limit: 200, null: false
    t.text "reason", null: false
    t.json "before_state", default: {}, null: false
    t.json "after_state", default: {}, null: false
    t.datetime "created_at", null: false
    t.index ["created_at"], name: "index_beskar_administrative_actions_on_created_at"
    t.index ["operation_id", "target_id"], name: "index_beskar_actions_on_operation_target", unique: true
    t.index ["target_id", "id"], name: "index_beskar_administrative_actions_on_target_id_and_id"
  end

  create_table "beskar_banned_ips", force: :cascade do |t|
    t.string "ip_address", null: false
    t.string "reason", null: false
    t.text "details"
    t.datetime "banned_at", null: false
    t.datetime "expires_at"
    t.boolean "permanent", default: false, null: false
    t.integer "violation_count", default: 1, null: false
    t.text "metadata"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["banned_at"], name: "index_beskar_banned_ips_on_banned_at"
    t.index ["expires_at"], name: "index_beskar_banned_ips_on_expires_at"
    t.index ["ip_address", "expires_at"], name: "index_beskar_banned_ips_on_ip_address_and_expires_at"
    t.index ["ip_address"], name: "index_beskar_banned_ips_on_ip_address", unique: true
  end

  create_table "beskar_security_events", force: :cascade do |t|
    t.string "user_type"
    t.integer "user_id"
    t.string "event_type", null: false
    t.string "ip_address"
    t.string "attempted_email"
    t.text "user_agent"
    t.json "metadata", default: {}
    t.integer "risk_score"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["attempted_email"], name: "index_beskar_security_events_on_attempted_email"
    t.index ["created_at"], name: "index_beskar_security_events_on_created_at"
    t.index ["event_type"], name: "index_beskar_security_events_on_event_type"
    t.index ["ip_address", "event_type", "created_at"], name: "index_security_events_on_ip_event_time"
    t.index ["ip_address"], name: "index_beskar_security_events_on_ip_address"
    t.index ["risk_score"], name: "index_beskar_security_events_on_risk_score"
    t.index ["user_type", "user_id", "event_type", "created_at"], name: "index_beskar_events_on_user_event_time"
    t.index ["user_type", "user_id"], name: "index_beskar_security_events_on_user"
  end

  create_table "beskar_security_states", force: :cascade do |t|
    t.string "key", null: false
    t.json "data", default: {}, null: false
    t.datetime "expires_at"
    t.integer "lock_version", default: 0, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_beskar_security_states_on_expires_at"
    t.index ["key"], name: "index_beskar_security_states_on_key", unique: true
  end

  create_table "devise_users", force: :cascade do |t|
    t.string "email", default: "", null: false
    t.string "encrypted_password", default: "", null: false
    t.string "reset_password_token"
    t.datetime "reset_password_sent_at"
    t.datetime "remember_created_at"
    t.integer "sign_in_count", default: 0, null: false
    t.datetime "current_sign_in_at"
    t.datetime "last_sign_in_at"
    t.string "current_sign_in_ip"
    t.string "last_sign_in_ip"
    t.string "confirmation_token"
    t.datetime "confirmed_at"
    t.datetime "confirmation_sent_at"
    t.string "unconfirmed_email"
    t.integer "failed_attempts", default: 0, null: false
    t.string "unlock_token"
    t.datetime "locked_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_devise_users_on_email", unique: true
    t.index ["reset_password_token"], name: "index_devise_users_on_reset_password_token", unique: true
  end

  create_table "sessions", force: :cascade do |t|
    t.integer "user_id", null: false
    t.string "ip_address"
    t.string "user_agent"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["user_id"], name: "index_sessions_on_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.string "email_address", null: false
    t.string "password_digest", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["email_address"], name: "index_users_on_email_address", unique: true
  end

  add_foreign_key "sessions", "users"
end
