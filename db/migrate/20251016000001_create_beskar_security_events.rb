# frozen_string_literal: true

class CreateBeskarSecurityEvents < ActiveRecord::Migration[8.0]
  def change
    create_table :beskar_security_events do |t|
      t.references :user, polymorphic: true, null: true, index: true
      t.string :event_type, null: false
      t.string :ip_address
      t.string :attempted_email
      t.text :user_agent
      t.json :metadata, default: -> { "('{}')" }
      t.integer :risk_score

      t.timestamps
    end

    add_index :beskar_security_events, :ip_address
    add_index :beskar_security_events, :event_type
    add_index :beskar_security_events, :attempted_email
    add_index :beskar_security_events, :created_at
    add_index :beskar_security_events, :risk_score
    add_index :beskar_security_events, [:ip_address, :event_type, :created_at],
      name: "index_security_events_on_ip_event_time"
  end
end
