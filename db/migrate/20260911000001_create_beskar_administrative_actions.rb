class CreateBeskarAdministrativeActions < ActiveRecord::Migration[8.0]
  def change
    create_table :beskar_administrative_actions do |t|
      t.string :actor, null: false, limit: 200
      t.string :action, null: false
      t.bigint :target_id, null: false
      t.string :operation_id, null: false, limit: 36
      t.string :request_id, null: false, limit: 200
      t.text :reason, null: false
      t.json :before_state, null: false, default: {}
      t.json :after_state, null: false, default: {}
      t.datetime :created_at, null: false
    end
    # No user/ban foreign key or cascading association: the action must survive
    # deletion of its live target. Retention is a separate, explicit operation.
    add_index :beskar_administrative_actions, [:operation_id, :target_id], unique: true,
      name: "index_beskar_actions_on_operation_target"
    add_index :beskar_administrative_actions, [:target_id, :id]
    add_index :beskar_administrative_actions, :created_at
  end
end
