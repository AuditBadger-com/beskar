require "test_helper"
require "csv"

class DashboardContractTest < ActionDispatch::IntegrationTest
  setup do
    Beskar.configuration.authenticate_admin = ->(_) { true }
  end

  test "model predicates filters exports and badges agree at every risk boundary" do
    scores = {0 => :low, 29 => :low, 30 => :medium, 60 => :medium, 61 => :medium,
              69 => :medium, 70 => :high, 85 => :high, 86 => :high, 89 => :high, 90 => :critical, 100 => :critical}
    events = scores.map do |score, level|
      event = create(:security_event, user: nil, risk_score: score, event_type: "boundary_probe")
      assert_equal level, event.risk_level
      assert_equal [:high, :critical].include?(level), event.high_risk?
      assert_equal level == :critical, event.critical_threat?
      get "/beskar/security_events/#{event.id}"
      assert_response :success
      assert_select ".badge-#{Beskar::RiskLevel::BADGES[level]}", text: "#{level.to_s.capitalize} Risk"
      event
    end
    Beskar::RiskLevel::RANGES.each_key do |level|
      expected = events.select { |event| scores[event.risk_score] == level }.map(&:id).sort
      assert_equal expected, Beskar::SecurityEvent.with_risk_level(level).order(:id).ids
      get "/beskar/security_events/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {event_type: "boundary_probe", risk_level: level}
      assert_equal expected, JSON.parse(response.body).map { |record| record["id"] }.sort
      get "/beskar/security_events", params: {event_type: "boundary_probe", risk_level: level}
      assert_select "tbody tr", count: expected.length
      assert_select "#risk_level option[value='#{level}']", text: Beskar::RiskLevel.filter_options.to_h.key(level.to_s)
    end
    assert_equal events.select(&:high_risk?).map(&:id).sort, Beskar::SecurityEvent.high_risk.order(:id).ids
    assert_equal events.select(&:critical_threat?).map(&:id).sort, Beskar::SecurityEvent.critical_risk.order(:id).ids
  end

  test "invalid scores are unknown and fractional averages use the same thresholds" do
    [nil, -1, 101, "90", Float::INFINITY, Float::NAN].each do |score|
      assert_nil Beskar::RiskLevel.for(score)
      assert_equal "neutral", Beskar::ApplicationController.new.send(:risk_level_class, score)
    end
    assert_equal :medium, Beskar::RiskLevel.for(69.9)
    assert_equal :high, Beskar::RiskLevel.for(89.9)
  end

  test "dashboard counters and distribution agree and exclude events outside the selected period" do
    travel_to Time.zone.local(2026, 9, 11, 12) do
      [29, 30, 69, 70, 89, 90].each { |score| create(:security_event, user: nil, risk_score: score, created_at: 10.minutes.ago) }
      create(:security_event, user: nil, risk_score: 95, created_at: 2.hours.ago)
      create(:security_event, user: nil, risk_score: 95, created_at: 1.hour.from_now)
      get "/beskar/dashboard", params: {time_range: "1h"}
      assert_response :success
      stats = controller_assigns.fetch("stats")
      assert_equal 6, stats[:total_events]
      assert_equal 3, stats[:high_risk_events]
      assert_equal 1, stats[:critical_threats]
      assert_equal({low: 1, medium: 2, high: 2, critical: 1}, controller_assigns.fetch("risk_distribution"))
      assert_select ".stat-change", text: "Score ≥ 70"
      assert_select ".stat-change", text: "Score ≥ 90"
    end
  end

  test "ban totals cover the full history while the displayed sample stays at twenty" do
    ban = create(:banned_ip)
    oldest = create(:security_event, user: nil, ip_address: ban.ip_address, risk_score: 100, created_at: 7.days.ago)
    24.times do |i|
      create(:security_event, user: nil, ip_address: ban.ip_address, risk_score: 10, created_at: (i + 1).minutes.ago)
    end
    create(:security_event, user: nil, ip_address: "198.51.100.99", risk_score: 0)
    get "/beskar/banned_ips/#{ban.id}"
    assert_response :success
    stats = controller_assigns.fetch("stats")
    assert_equal 25, stats[:total_events]
    assert_equal 13.6, stats[:avg_risk_score]
    assert_equal 100, stats[:max_risk_score]
    assert_equal oldest.created_at, stats[:first_seen]
    assert_equal 20, controller_assigns.fetch("related_events").size
    assert_select "tbody tr", count: 20
  end

  test "native and Devise user labels share display and export privacy policy" do
    Rails.application.config.stubs(:filter_parameters).returns([])
    [create(:user, email_address: "native-label@example.com"), create(:devise_user, email: "devise-label@example.com")].each do |user|
      event = create(:security_event, user: user)
      ban = create(:banned_ip, ip_address: event.ip_address)
      email = user.try(:email) || user.try(:email_address)
      ["/beskar/dashboard", "/beskar/security_events", "/beskar/security_events/#{event.id}", "/beskar/banned_ips/#{ban.id}"].each do |path|
        get path
        assert_response :success
        assert response.body.include?(email), "#{path} should display the permitted email"
      end
      get "/beskar/security_events/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}
      assert_includes CSV.parse(response.body, headers: true).map { |row| row["User"] }, email
      get "/beskar/security_events/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}
      assert_equal email, JSON.parse(response.body).find { |row| row["id"] == event.id }.dig("user", "email")
      ban.destroy!
    end
  end

  test "native email_address filters apply to every display and export" do
    Rails.application.config.stubs(:filter_parameters).returns([:email_address])
    user = create(:user, email_address: "private-native@example.com")
    event = create(:security_event, user: user)
    ban = create(:banned_ip, ip_address: event.ip_address)
    ["/beskar/dashboard", "/beskar/security_events", "/beskar/security_events/#{event.id}",
      "/beskar/banned_ips/#{ban.id}", "/beskar/security_events/export.csv", "/beskar/security_events/export.json"].each do |path|
      get path, headers: {"X-Beskar-Audit-Reason" => "Privacy regression"}
      assert_response :success
      refute response.body.include?(user.email_address), "#{path} should not disclose the email"
      assert response.body.include?("[FILTERED]"), "#{path} should display the filter marker"
    end
  end

  test "event ordering is stable when timestamps are identical" do
    now = Time.current
    events = 3.times.map { create(:security_event, user: nil, created_at: now) }
    get "/beskar/security_events", params: {per_page: 2}
    assert_equal events.last(2).reverse.map(&:id), controller_assigns.fetch("events").map(&:id)
    get "/beskar/security_events", params: {per_page: 2, page: 2}
    assert_equal [events.first.id], controller_assigns.fetch("events").map(&:id)
  end

  test "search and legacy email filters compose identically for pages and exports" do
    Rails.application.config.stubs(:filter_parameters).returns([])
    legacy = create(:security_event, user: nil, risk_score: 75,
      metadata: {attempted_email: "legacy@example.com", message: "needle%value"})
    create(:security_event, user: nil, risk_score: 10,
      metadata: {attempted_email: "legacy@example.com", message: "needle%value"})
    create(:security_event, user: nil, risk_score: 75,
      metadata: {message: "legacy@example.com needle%value"})
    filters = {email: "LEGACY@", search: "NEEDLE%VALUE", risk_level: "high"}
    get "/beskar/security_events", params: filters
    assert_response :success
    assert_equal [legacy.id], controller_assigns.fetch("events").ids
    get "/beskar/security_events/export.json", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: filters
    assert_response :success
    assert_equal [legacy.id], JSON.parse(response.body).map { |record| record["id"] }
    get "/beskar/security_events/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: filters
    assert_response :success
    assert_equal [legacy.id.to_s], CSV.parse(response.body, headers: true).map { |row| row["ID"] }
  end

  test "dashboard reuses grouped event counts rather than repeating each overview query" do
    3.times { create(:security_event, user: nil, risk_score: 75) }
    statements = capture_selects { get "/beskar/dashboard" }
    aggregates = statements.select { |sql| sql.include?("beskar_security_events") && sql.match?(/COUNT\(|AVG\(|MAX\(/) }
    assert_response :success
    assert_equal 3, aggregates.length, aggregates.join("\n")
  end

  test "ban history preloads users instead of one lookup per event" do
    ban = create(:banned_ip)
    5.times { create(:security_event, ip_address: ban.ip_address) }
    statements = capture_selects { get "/beskar/banned_ips/#{ban.id}" }
    assert_response :success
    assert_equal 1, statements.count { |sql| sql.include?("FROM #{User.quoted_table_name}") }, statements.join("\n")
  end

  test "only implemented controllers have public engine routes" do
    controllers = Beskar::Engine.routes.routes.filter_map { |route| route.defaults[:controller] }.uniq
    assert_equal %w[beskar/administrative_actions beskar/banned_ips beskar/dashboard beskar/security_events], controllers.sort
    ["/api/v1/security_events", "/api/v1/security_events/1", "/api/v1/security_events/stats",
      "/api/v1/banned_ips", "/api/v1/banned_ips/1"].each do |path|
      assert_raises(ActionController::RoutingError) { Beskar::Engine.routes.recognize_path(path, method: :get) }
    end
    assert_raises(ActionController::RoutingError) { Beskar::Engine.routes.recognize_path("/api/v1/banned_ips", method: :post) }
    assert_raises(ActionController::RoutingError) { Beskar::Engine.routes.recognize_path("/api/v1/banned_ips/1", method: :delete) }
  end

  private

  def controller_assigns
    response.request.env.fetch("action_controller.instance").view_assigns
  end

  def capture_selects
    statements = []
    callback = ->(*args) do
      data = args.last
      statements << data[:sql] if !data[:cached] && data[:sql].start_with?("SELECT")
    end
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
    statements
  end
end
