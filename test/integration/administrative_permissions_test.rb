require "test_helper"

class AdministrativePermissionsTest < ActionDispatch::IntegrationTest
  setup do
    Beskar.configuration.authenticate_admin = ->(_) { true }
    @ban = create(:banned_ip)
    @event = create(:security_event)
  end

  test "authentication alone grants no dashboard permission" do
    Beskar.configuration.authorize_admin = nil
    ["/beskar/dashboard", "/beskar/security_events", "/beskar/administrative_actions",
      "/beskar/banned_ips/new", "/beskar/security_events/export.json"].each do |path|
      get path
      assert_response :forbidden
    end
  end

  test "read export ban management and audit history require independent grants" do
    Beskar.configuration.authorize_admin = ->(_request, permission) { permission == :read }
    get "/beskar/security_events"
    assert_response :success
    assert_no_difference "Beskar::AdministrativeAction.count" do
      get "/beskar/security_events/export.json", params: {audit_reason: "Investigation"}
      assert_response :forbidden
      delete "/beskar/banned_ips/#{@ban.id}", params: {audit_reason: "Investigation"}
      assert_response :forbidden
      get "/beskar/administrative_actions"
      assert_response :forbidden
    end
    assert Beskar::BannedIp.exists?(@ban.id)
    Beskar.configuration.authorize_admin = ->(_request, permission) { permission == :read_audit }
    get "/beskar/administrative_actions"
    assert_response :success
    get "/beskar/security_events"
    assert_response :forbidden
  end

  test "authorization callback exceptions and truthy non-booleans do not grant access" do
    Beskar.configuration.authorize_admin = ->(_, _) { "true" }
    get "/beskar/dashboard"
    assert_response :forbidden
    Beskar.configuration.authorize_admin = ->(_, _) { raise "private failure" }
    get "/beskar/dashboard"
    assert_response :service_unavailable
    refute_includes response.body, "private failure"
  end

  test "exports require an actor and reason and record resource filter and result boundaries" do
    Beskar.configuration.audit_actor = ->(_) {}
    get "/beskar/security_events/export.json", params: {audit_reason: "Investigate incident"}
    assert_response :service_unavailable
    Beskar.configuration.audit_actor = ->(_) { "admin:exporter" }
    get "/beskar/security_events/export.json"
    assert_response :unprocessable_content
    assert_difference "Beskar::AdministrativeAction.count", 1 do
      get "/beskar/security_events/export.json", params: {audit_reason: "Investigate incident", ip_address: @event.ip_address}
      assert_response :success
    end
    entry = Beskar::AdministrativeAction.last
    assert_equal "audit_exported", entry.action
    assert_equal "SecurityEvent", entry.target_type
    assert_equal "admin:exporter", entry.actor
    assert_equal "Investigate incident", entry.reason
    assert_equal 1, entry.after_state["count"]
    assert_equal @event.id, entry.after_state["highest_id"]
    assert_equal @event.ip_address, entry.after_state.dig("filters", "ip_address")
    assert_equal response.headers["X-Request-Id"], entry.request_id
    assert_nil entry.target_id
  end

  test "a required export journal failure releases no audit data" do
    Beskar::AdministrativeAction.stubs(:create!).raises(ActiveRecord::StatementInvalid, "private storage error")
    %w[security_events banned_ips].each do |resource|
      get "/beskar/#{resource}/export.json", params: {audit_reason: "Investigate incident"}
      assert_response :service_unavailable
      refute_includes response.body, @event.ip_address
      refute_includes response.body, @ban.ip_address
      refute_includes response.body, "private storage error"
    end
  end

  test "security events reject normal mutation and deletion without changing stored evidence" do
    stored = Beskar::SecurityEvent.where(id: @event.id).pick(:metadata)
    assert_raises(ActiveRecord::ReadOnlyRecord) { @event.update!(risk_score: 100) }
    assert_raises(ActiveRecord::ReadOnlyRecord) { @event.update_columns(metadata: {}) }
    assert_raises(ActiveRecord::ReadOnlyRecord) { @event.destroy! }
    assert_raises(ActiveRecord::ReadOnlyRecord) { @event.delete }
    assert_equal stored, Beskar::SecurityEvent.where(id: @event.id).pick(:metadata)
  end
end
