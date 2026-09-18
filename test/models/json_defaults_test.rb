require "test_helper"
require "active_record/connection_adapters/mysql2_adapter"
require_relative "../../db/migrate/20251016000001_create_beskar_security_events"
require_relative "../../db/migrate/20260910000001_create_beskar_security_states"
require_relative "../../db/migrate/20260911000001_create_beskar_administrative_actions"

class JsonDefaultsTest < ActiveSupport::TestCase
  JSON_FIELDS = {
    Beskar::SecurityEvent => [:metadata],
    Beskar::SecurityState => [:data],
    Beskar::AdministrativeAction => [:before_state, :after_state]
  }.freeze

  test "new records have independent empty JSON objects on every adapter" do
    JSON_FIELDS.each do |model, fields|
      first, second = model.new, model.new
      fields.each do |field|
        assert_equal({}, first[field])
        first[field]["changed"] = true
        assert_equal({}, second[field])
      end
    end
    action = Beskar::AdministrativeAction.new
    action.before_state["changed"] = true
    assert_empty action.after_state
  end

  test "database defaults work for inserts that bypass model initialization" do
    records = {
      Beskar::SecurityEvent => {event_type: "login_failure", ip_address: "192.0.2.10", risk_score: 0},
      Beskar::SecurityState => {key: "json-default-probe"},
      Beskar::AdministrativeAction => {
        actor: "test:defaults", action: "configuration_changed", target_type: "Configuration",
        operation_id: SecureRandom.uuid, request_id: "default-probe", reason: "Verify database defaults"
      }
    }
    records.each do |model, attributes|
      connection = model.connection
      timestamps = {created_at: Time.current, updated_at: Time.current}.slice(*model.column_names.map(&:to_sym))
      values = attributes.merge(timestamps)
      columns = values.keys.map { |name| connection.quote_column_name(name) }.join(", ")
      literals = values.values.map { |value| connection.quote(value) }.join(", ")
      connection.execute("INSERT INTO #{connection.quote_table_name(model.table_name)} (#{columns}) VALUES (#{literals})")
      JSON_FIELDS.fetch(model).each do |field|
        assert_equal({}, model.where(attributes).pick(field), "#{model.name}.#{field} needs a database default")
      end
    end
  end

  test "fresh migrations compile JSON defaults as MySQL expressions" do
    adapter = mysql_sql_compiler
    [CreateBeskarSecurityEvents, CreateBeskarSecurityStates, CreateBeskarAdministrativeActions].each do |migration_class|
      table = adapter.send(:create_table_definition, "defaults_probe")
      migration = migration_class.new
      migration.stubs(:create_table).yields(table)
      migration.stubs(:add_index)
      migration.change
      assert_mysql_json_defaults(adapter, table.columns)
    end
  end

  test "the checked in schema preserves portable JSON defaults and foreign key widths" do
    adapter = mysql_sql_compiler
    tables = {}
    schema = ActiveRecord::Schema[8.0].new
    # Evaluate the actual schema DSL without touching the test database.
    schema.define_singleton_method(:define) { |*, &block| instance_eval(&block) }
    schema.define_singleton_method(:create_table) do |name, **, &block|
      tables[name] = adapter.send(:create_table_definition, name)
      block.call(tables[name])
    end
    schema.stubs(:add_foreign_key)
    ActiveRecord::Schema[8.0].stubs(:new).returns(schema)
    load File.expand_path("../dummy/db/schema.rb", __dir__)

    assert_mysql_json_defaults(adapter, tables.values.flat_map(&:columns))
    # Rails' MySQL create_table uses bigint IDs; a SQLite-dumped integer FK fails.
    assert_equal :bigint, tables.fetch("sessions").columns.find { |column| column.name == "user_id" }.type
  end

  private

  def mysql_sql_compiler
    # This checks Rails' real SQL generation, not execution on a MySQL server.
    ActiveRecord::ConnectionAdapters::Mysql2Adapter.new(adapter: "mysql2", database: "unused").tap do |adapter|
      adapter.expects(:connect).never
    end
  end

  def assert_mysql_json_defaults(adapter, columns)
    json_columns = columns.select { |column| column.type == :json }
    assert_not_empty json_columns
    json_columns.each do |column|
      sql = adapter.schema_creation.accept(column)
      assert_includes sql, "json DEFAULT ('{}')", "Nonportable JSON default: #{sql}"
    end
  end
end
