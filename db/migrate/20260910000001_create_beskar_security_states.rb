class CreateBeskarSecurityStates < ActiveRecord::Migration[8.0]
  def change
    create_table :beskar_security_states do |t|
      t.string :key, null: false
      t.json :data, null: false, default: {}
      t.datetime :expires_at
      t.integer :lock_version, null: false, default: 0
      t.timestamps
    end
    add_index :beskar_security_states, :key, unique: true
    add_index :beskar_security_states, :expires_at
    add_index :beskar_security_events, [:user_type, :user_id, :event_type, :created_at], name: "index_beskar_events_on_user_event_time"
  end
end
