require "test_helper"

class DashboardFormsTest < ActionDispatch::IntegrationTest
  setup do
    Beskar.configuration.authenticate_admin = ->(_) { true }
    Beskar.configuration.audit_actor = ->(_) { "test:forms" }
  end

  test "UTC expiry survives create edit roundtrip in a non UTC application zone" do
    Time.use_zone("America/New_York") do
      create_ban(expires_at: "2030-11-03T01:30:00.123456")
      assert_response :redirect
      ban = Beskar::BannedIp.last
      assert_equal "2030-11-03T01:30:00.123456Z", ban.expires_at.utc.iso8601(6)
      get "/beskar/banned_ips/#{ban.id}/edit"
      assert_select "label[for='banned_ip_expires_at']", text: "Expiry Date/Time (UTC)"
      assert_select "input[name='banned_ip[expires_at]'][value='2030-11-03T01:30:00.123'][step='0.001']"
      assert_no_difference "Beskar::AdministrativeAction.count" do
        patch "/beskar/banned_ips/#{ban.id}", params: {audit_reason: "Unchanged", expiry_precision: "milliseconds",
                                                       banned_ip: {expires_at: "2030-11-03T01:30:00.123"}}
        assert_response :redirect
      end
      assert_equal "2030-11-03T01:30:00.123456Z", ban.reload.expires_at.utc.iso8601(6)
    end
  end

  test "ISO offset inputs identify explicit instants including daylight saving folds" do
    ["2030-11-03T01:30:00-04:00", "2030-11-03T01:30:00-05:00", "2030-03-31T02:30:00+02:00"].each do |value|
      create_ban(expires_at: value)
      assert_response :redirect
      assert_equal Time.iso8601(value), Beskar::BannedIp.last.expires_at
      Beskar::BannedIp.last.destroy!
    end
    create_ban(expires_at: "2030-03-31T02:30")
    assert_response :redirect
    assert_equal Time.utc(2030, 3, 31, 2, 30), Beskar::BannedIp.last.expires_at
  end

  test "invalid dates cannot silently normalize or fall back to a default ban" do
    ["0000-01-01T10:00", "2030-02-30T10:00", "2030-01-01T24:00", "2030-01-01T10:00:60", "tomorrow", "2030-01-01", ["2030-01-01T10:00"],
      "2030-01-01T10:00+25:00", "2030-01-01T10:00:00.1234567Z", "x" * 10000].each do |value|
      assert_no_difference ["Beskar::BannedIp.count", "Beskar::AdministrativeAction.count"] do
        create_ban(expires_at: value)
        assert_response :unprocessable_content
      end
    end
    ban = create(:banned_ip)
    previous = ban.expires_at
    patch "/beskar/banned_ips/#{ban.id}", params: {audit_reason: "Invalid edit", banned_ip: {expires_at: "2030-02-30T10:00"}}
    assert_response :unprocessable_content
    assert_equal previous, ban.reload.expires_at
  end

  test "duration presets and defaults are server relative and malformed presets are rejected" do
    travel_to Time.utc(2030, 3, 10, 7, 30) do
      create_ban(duration: "3600")
      assert_response :redirect
      assert_equal 1.hour.from_now, Beskar::BannedIp.last.expires_at
      Beskar::BannedIp.last.destroy!
      create_ban
      assert_response :redirect
      assert_equal 24.hours.from_now, Beskar::BannedIp.last.expires_at
      Beskar::BannedIp.last.destroy!
      ["0", "-1", "1h", "3600seconds", "1.5", "7776001", ["3600"], [], {}].each do |duration|
        assert_no_difference "Beskar::BannedIp.count" do
          create_ban(duration: duration, json: true)
          assert_response :unprocessable_content
        end
      end
    end
  end

  test "permanent ignores temporary input and reverting to temporary requires an expiry" do
    create_ban(ban_type: "permanent", expires_at: "invalid", duration: "invalid")
    assert_response :redirect
    ban = Beskar::BannedIp.last
    assert ban.permanent?
    assert_nil ban.expires_at
    patch "/beskar/banned_ips/#{ban.id}", params: {audit_reason: "Temporary", banned_ip: {permanent: "false", expires_at: ""}}
    assert_response :unprocessable_content
    assert ban.reload.permanent?
    assert_select "textarea[name='audit_reason']", text: "Temporary"
  end

  test "rendered dashboard has nonce scripts no inline handlers or method links and native navigation" do
    ban = create(:banned_ip)
    ["/beskar/dashboard", "/beskar/security_events", "/beskar/banned_ips", "/beskar/banned_ips/new",
      "/beskar/banned_ips/#{ban.id}/edit", "/beskar/banned_ips/#{ban.id}/review?operation=unban"].each do |path|
      get path
      assert_response :success
      nonce = css_select("script").first["nonce"]
      assert nonce.present?
      assert_includes response.headers["Content-Security-Policy"], "'nonce-#{nonce}'"
      assert_select "body[data-beskar-dashboard][data-turbo='false']"
      assert_select "script:not([nonce]), [onclick], [onchange], [onsubmit], [oninput], a[data-turbo-method]", count: 0
    end
  end

  test "page size forms exclude stale page size and page fields and work without scripts" do
    %w[security_events banned_ips].each do |resource|
      get "/beskar/#{resource}", params: {per_page: 10, page: 3, status: "active"}
      assert_response :success
      assert_select "form:has(select[name='per_page'])" do
        assert_select "input[type='hidden'][name='per_page'], input[type='hidden'][name='page']", count: 0
        assert_select "input[type='submit'][value='Apply page size']"
        assert_select "input[type='hidden'][name='status'][value='active']"
      end
    end
  end

  private

  def create_ban(expires_at: nil, duration: nil, ban_type: "temporary", json: false)
    post "/beskar/banned_ips", params: {audit_reason: "Form regression", ban_type: ban_type, duration: duration,
                                        banned_ip: {ip_address: "198.51.100.219", reason: "manual_ban", expires_at: expires_at}}, as: (json ? :json : nil)
  end
end
