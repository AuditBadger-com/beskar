class ExpandAdministrativeActionTargets < ActiveRecord::Migration[8.0]
  def change
    add_column :beskar_administrative_actions, :target_type, :string, null: false, default: "BannedIp"
    change_column_null :beskar_administrative_actions, :target_id, true
  end
end
