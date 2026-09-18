require "test_helper"
require "csv"

class AuditPrivacyTest < ActionDispatch::IntegrationTest
  setup do
    Beskar.configuration.authenticate_admin = ->(_) { true }
  end

  test "audit capture honors built-in and host filters including nested and custom data" do
    Rails.application.config.stubs(:filter_parameters).returns([:custom_private])
    event = Beskar::SecurityEvent.create!(event_type: "test", ip_address: "198.51.100.1", risk_score: 1,
      user_agent: "header\n" + "a" * 1000, metadata: {session_id: "SECRET_SESSION", custom_private: "SECRET_CUSTOM",
                                                      nested: {access_token: "SECRET_TOKEN", exception_message: "SECRET_EXCEPTION", allowed: true}})
    refute_includes event.reload.metadata.to_json, "SECRET_"
    assert_equal true, event.metadata.dig("nested", "allowed")
    assert_operator event.user_agent.length, :<=, 500
    refute_match(/[\r\n]/, event.user_agent)
  end

  test "host email filtering does not remove account association or rate accounting" do
    user = create(:devise_user)
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.1")
    event = user.track_authentication_event(request, :success)
    assert_equal "[FILTERED]", event.attempted_email
    assert_equal user, event.user
    assert_equal 1, Beskar::Services::RateLimiter.check_account_rate_limit(user)[:count]
  end

  test "legacy metadata is redacted on display and export without rewriting stored rows" do
    event = create(:security_event)
    Beskar::SecurityEvent.where(id: event.id).update_all(metadata: {session_id: "SECRET_LEGACY", nested: {password: "SECRET_LEGACY"}, safe: "visible"})
    assert_equal "[FILTERED]", event.reload.metadata["session_id"]
    assert_includes Beskar::SecurityEvent.where(id: event.id).pick(:metadata).to_json, "SECRET_LEGACY"
    get "/beskar/security_events/#{event.id}"
    assert_response :success
    refute_includes response.body, "SECRET_LEGACY"
    get "/beskar/security_events/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}
    assert_response :success
    refute_includes response.body, "SECRET_LEGACY"
    assert_includes response.body, "visible"
  end

  test "partial model projections remain readable" do
    event = create(:security_event)
    partial = Beskar::SecurityEvent.select(:id, :event_type).find(event.id)
    assert_equal event.event_type, partial.event_type
    ban = create(:banned_ip)
    assert_equal ban.reason, Beskar::BannedIp.select(:id, :reason).find(ban.id).reason
  end

  test "ban audit redaction protects legacy UI and JSON without changing ban authority" do
    ban = create(:banned_ip, ip_address: "198.51.100.23", permanent: true)
    ban.update_columns(metadata: {authorization: "SECRET_LEGACY", safe: "visible"})
    Rails.application.config.stubs(:filter_parameters).returns([:ip_address])
    assert Beskar::BannedIp.banned?(ban.ip_address)
    get "/beskar/banned_ips/#{ban.id}"
    assert_response :success
    refute_includes response.body, "SECRET_LEGACY"
    get "/beskar/banned_ips/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}
    assert_response :success
    record = JSON.parse(response.body).find { |row| row["id"] == ban.id }
    assert_equal "[FILTERED]", record["metadata"]["authorization"]
    assert_equal "visible", record["metadata"]["safe"]
    assert_equal "198.51.100.23", record["ip_address"]
    assert_equal true, record["permanent"]
    assert_includes Beskar::BannedIp.where(id: ban.id).pick(:metadata).to_json, "SECRET_LEGACY"
  end

  test "metadata depth size and non-finite numbers are bounded" do
    data = {value: Float::INFINITY}
    100.times { data = {nested: data} }
    result = Beskar::Services::AuditData.metadata(data)
    assert_includes result.to_json, "[TRUNCATED]"
    assert_nil Beskar::Services::AuditData.metadata(value: Float::NAN)["value"]
    large = 64.times.to_h { |i| ["field#{i}", "a" * 10_000] }
    assert_operator Beskar::Services::AuditData.metadata(large).to_json.bytesize, :<=, 65_536
  end

  test "both CSV exports neutralize formula prefixes and preserve column boundaries" do
    Rails.application.config.stubs(:filter_parameters).returns([])
    payloads = ["=1+1", "+1+1", "-1+1", "@SUM(1,2)", "\t=1+1", "\uFEFF=1+1", "＝1+1", 'quote",=1+1']
    payloads.each_with_index do |payload, i|
      create(:security_event, event_type: "csv_probe", attempted_email: payload, user: nil, user_agent: payload, metadata: {details: payload})
      create(:banned_ip, ip_address: "198.51.100.#{i + 1}", reason: payload, details: payload)
    end
    get "/beskar/security_events/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {event_type: "csv_probe"}
    assert_response :success
    rows = CSV.parse(response.body, headers: true)
    assert_equal 8, rows.length
    assert rows.all? { |row| row.fields.length == 8 }
    assert_equal 7, rows.count { |row| row["User Agent"].start_with?("text: ") }
    get "/beskar/banned_ips/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}
    rows = CSV.parse(response.body, headers: true)
    assert rows.all? { |row| row.fields.length == 7 }
    assert_equal 7, rows.count { |row| row["Reason"].start_with?("text: ") }
    get "/beskar/security_events/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {event_type: "csv_probe"}
    assert JSON.parse(response.body).any? { |event| event["user_agent"] == "=1+1" }
    assert_includes response.headers["Cache-Control"], "no-store"
  end

  test "export is bounded and cursor pages neither duplicate nor skip records" do
    now = Time.current
    Beskar::SecurityEvent.insert_all!(1001.times.map do
      {event_type: "cursor_probe", ip_address: "198.51.100.1", risk_score: 0, metadata: {}, created_at: now, updated_at: now}
    end)
    get "/beskar/security_events/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {event_type: "cursor_probe"}
    first = JSON.parse(response.body)
    assert_equal 1000, first.length
    assert_equal "true", response.headers["X-Beskar-Export-Truncated"]
    cursor = response.headers["X-Beskar-Next-Cursor"]
    assert_equal first.last["id"].to_s, cursor
    get "/beskar/security_events/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {event_type: "cursor_probe", before_id: cursor}
    second = JSON.parse(response.body)
    assert_equal 1, second.length
    assert_equal "false", response.headers["X-Beskar-Export-Truncated"]
    assert_empty first.map { |event| event["id"] } & second.map { |event| event["id"] }
  end

  test "both export endpoints reject malformed cursors and require authorization" do
    ["security_events", "banned_ips"].each do |resource|
      ["garbage", "-1", "0", "9223372036854775808", ["123"]].each do |cursor|
        get "/beskar/#{resource}/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {before_id: cursor}
        assert_response :unprocessable_content
        assert_includes response.headers["Cache-Control"], "no-store"
      end
      Beskar.configuration.authenticate_admin = ->(_) { false }
      get "/beskar/#{resource}/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}
      assert_response :not_found
      Beskar.configuration.authenticate_admin = ->(_) { true }
    end
  end

  test "ban exports use the same bounded cursor contract and retain filters" do
    now = Time.current
    Beskar::BannedIp.insert_all!(1001.times.map do |i|
      {ip_address: "198.18.#{i / 256}.#{i % 256}", reason: "cursor_probe", metadata: "{}",
       permanent: true, banned_at: now, created_at: now, updated_at: now}
    end)
    create(:banned_ip, reason: "not_in_export")
    get "/beskar/banned_ips/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {reason: "cursor_probe"}
    first = JSON.parse(response.body)
    assert_equal 1000, first.length
    assert_equal "true", response.headers["X-Beskar-Export-Truncated"]
    cursor = response.headers["X-Beskar-Next-Cursor"]
    assert_equal first.last["id"].to_s, cursor
    get "/beskar/banned_ips/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {reason: "cursor_probe", before_id: cursor}
    second = JSON.parse(response.body)
    assert_equal 1, second.length
    assert_equal "false", response.headers["X-Beskar-Export-Truncated"]
    assert_empty first.map { |record| record["id"] } & second.map { |record| record["id"] }
    assert (first + second).all? { |record| record["reason"] == "cursor_probe" }
  end
end
