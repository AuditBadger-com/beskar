require "test_helper"

class EventSearchTest < ActiveSupport::TestCase
  setup do
    Rails.application.config.stubs(:filter_parameters).returns([])
    @search = Beskar::Services::EventSearch.new(Beskar::SecurityEvent.all)
  end

  test "general search includes event types and nested metadata with ASCII case folding" do
    metadata = create(:security_event, user: nil, metadata: {nested: {message: "NeedleValue"}})
    event_type = create(:security_event, user: nil, event_type: "NEEDLE_event")
    create(:security_event, user: nil, metadata: {message: "unrelated"})
    assert_equal [metadata.id, event_type.id].sort, @search.search("NEEDLE").order(:id).ids
  end

  test "email filter uses the attempted-email column or its exact legacy fallback" do
    current = create(:security_event, user: nil, attempted_email: "Current@Example.com")
    legacy = create(:security_event, user: nil, metadata: {attempted_email: "Legacy@Example.com"})
    create(:security_event, user: nil, metadata: {message: "legacy@example.com"})
    overridden = create(:security_event, user: nil, attempted_email: "replacement@host.test")
    Beskar::SecurityEvent.where(id: overridden.id).update_all(metadata: {attempted_email: "Legacy@Example.com"})
    assert_equal [current.id], @search.email("CURRENT@").ids
    assert_equal [legacy.id], @search.email("LEGACY@").ids
    assert_equal [overridden.id], @search.email("replacement@").ids
  end

  test "missing null and empty legacy emails do not match a real address" do
    [{}, {attempted_email: nil}, {attempted_email: ""}].each do |data|
      create(:security_event, user: nil, metadata: data)
    end
    assert_empty @search.email("example.com").ids
  end

  test "wildcards escape characters and SQL-shaped strings are literal search text" do
    ["percent%probe", "under_score", "bang!probe", "back\\slash", "' OR 1=1 --"].each do |term|
      event = create(:security_event, user: nil, user_agent: term, attempted_email: term)
      create(:security_event, user: nil, user_agent: "unrelated", attempted_email: "unrelated")
      assert_equal [event.id], @search.search(term).ids
      assert_equal [event.id], @search.email(term).ids
    end
  end

  test "search composes with existing scopes and ignores non-text values" do
    event = create(:security_event, user: nil, risk_score: 80, metadata: {message: "needle"})
    create(:security_event, user: nil, risk_score: 10, metadata: {message: "needle"})
    scoped = Beskar::Services::EventSearch.new(Beskar::SecurityEvent.high_risk)
    assert_equal [event.id], scoped.search("needle").ids
    [nil, "", [], {value: "needle"}].each do |value|
      assert_equal [event.id], scoped.search(value).ids
      assert_equal [event.id], scoped.email(value).ids
    end
  end

  test "overlong search input is bounded and unsupported legacy extractors fail explicitly" do
    assert_operator @search.search("x" * 100_000).to_sql.bytesize, :<, 2048
    connection = Beskar::SecurityEvent.connection
    connection.stubs(:adapter_name).returns("UnverifiedAdapter")
    error = assert_raises(ArgumentError) { @search.email("needle") }
    assert_equal "Beskar email search does not support this database adapter", error.message
  ensure
    connection.unstub(:adapter_name)
  end

  test "SQL expressions are adapter-specific without applying LIKE directly to JSON" do
    connection = Beskar::SecurityEvent.connection
    {"PostgreSQL" => [" AS TEXT)", "->> 'attempted_email'"],
     "SQLite" => [" AS TEXT)", "json_extract("],
     "Mysql2" => [" AS CHAR)", "JSON_UNQUOTE(JSON_EXTRACT("],
     "Trilogy" => [" AS CHAR)", "JSON_UNQUOTE(JSON_EXTRACT("]}.each do |adapter, (cast, extraction)|
      connection.stubs(:adapter_name).returns(adapter)
      assert_includes @search.search("needle").to_sql, cast
      email_sql = @search.email("needle").to_sql
      assert_includes email_sql, extraction
      assert_includes email_sql, "COALESCE("
      assert_includes email_sql, "ESCAPE '!'"
    end
  ensure
    connection.unstub(:adapter_name)
  end
end
