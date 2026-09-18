require "test_helper"
require "csv"

class AuditLifecycleTest < ActionDispatch::IntegrationTest
  setup do
    Beskar.configuration.authenticate_admin = ->(_) { true }
  end

  [:user, :devise_user].each do |factory|
    test "deleting #{factory} retains every stored event field and its original identity" do
      user = create(factory)
      events = %w[login_success login_failure authentication_blocked account_locked].map do |type|
        create(:security_event, user: user, event_type: type, ip_address: "198.51.100.212")
      end
      # Simulate legacy evidence that read-time redaction must not rewrite.
      Beskar::SecurityEvent.where(id: events.first.id).update_all(attempted_email: "retained@example.com",
        metadata: {session_id: "SECRET_LEGACY", safe: "original evidence"})
      stored = raw_events(events)
      # Exercise deletion with the association already loaded, too.
      user.security_events.load

      assert_no_difference "Beskar::SecurityEvent.count" do
        user.destroy!
      end

      assert_equal stored, raw_events(events)
      events.each do |event|
        assert_nil event.reload.user
        assert_equal user.class.polymorphic_name, event.user_type
        assert_equal user.id, event.user_id
      end

      ban = create(:banned_ip, ip_address: "198.51.100.212")
      ["/beskar/dashboard", "/beskar/security_events", "/beskar/security_events/#{events.first.id}",
        "/beskar/banned_ips/#{ban.id}"].each do |path|
        get path
        assert_response :success
        refute_includes response.body, "SECRET_LEGACY"
        refute_includes response.body, "retained@example.com"
      end

      get "/beskar/security_events/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {ip_address: "198.51.100.212"}
      assert_response :success
      rows = JSON.parse(response.body)
      assert_equal events.map(&:id).sort, rows.map { |row| row.fetch("id") }.sort
      rows.each do |row|
        assert_equal user.class.polymorphic_name, row.fetch("user_type")
        assert_equal user.id, row.fetch("user_id")
        refute row.key?("user")
      end
      refute_includes response.body, "SECRET_LEGACY"
      refute_includes response.body, "retained@example.com"

      get "/beskar/security_events/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {ip_address: "198.51.100.212"}
      assert_response :success
      assert_equal 4, CSV.parse(response.body, headers: true).length
      refute_includes response.body, "SECRET_LEGACY"
      refute_includes response.body, "retained@example.com"
      assert_equal stored, raw_events(events), "Rendering and export must not rewrite retained evidence"
    end
  end

  test "rolled back account deletion and unrelated deletion leave event rows untouched" do
    [:user, :devise_user].each do |factory|
      user = create(factory)
      event = create(:security_event, user: user)
      anonymous = create(:security_event, user: nil, event_type: "login_failure")
      stored = raw_events([event, anonymous])

      user.class.transaction(requires_new: true) do
        user.destroy!
        assert_equal stored, raw_events([event, anonymous])
        raise ActiveRecord::Rollback
      end
      assert_equal user.id, event.reload.user.id
      create(factory).destroy!
      assert_equal stored, raw_events([event, anonymous])
    end
  end

  private

  def raw_events(events)
    # Pluck bypasses after_find sanitization and compares every persisted column.
    Beskar::SecurityEvent.where(id: events.map(&:id)).order(:id).pluck(*Beskar::SecurityEvent.column_names)
  end
end
