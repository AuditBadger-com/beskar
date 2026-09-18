require "test_helper"

class RiskEvidenceTest < ActionDispatch::IntegrationTest
  BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36"

  setup do
    @user = create(:devise_user, password: "password123")
    @ny = {country: "United States", country_code: "US", latitude: 40.7128, longitude: -74.0060, provider: "maxmind"}
    @london = {country: "United Kingdom", country_code: "GB", latitude: 51.5074, longitude: -0.1278, provider: "maxmind"}
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 25, immediate_signout: true, notify_user: false)
    Beskar::Services::GeolocationService.any_instance.stubs(:locate).with("198.51.100.1").returns(@ny)
    Beskar::Services::GeolocationService.any_instance.stubs(:locate).with("198.51.100.2").returns(@london)
  end

  test "real admitted login history drives travel lock and matching evidence" do
    login("198.51.100.1")
    assert_response :redirect
    previous = @user.security_events.login_successes.last
    assert_equal 1, previous.risk_score
    assert_equal true, previous.metadata.dig("authentication", "allowed")
    delete "/devise_users/sign_out"
    travel 60.seconds do
      login("198.51.100.2")
      assert @user.reload.access_locked?
      event = @user.security_events.find_by!(event_type: "authentication_blocked")
      assert_equal 31, event.risk_score
      assert_equal true, event.metadata.dig("geolocation", "impossible_travel")
      travel_evidence = event.metadata.dig("geolocation", "travel")
      assert_equal previous.id, travel_evidence["previous_event_id"]
      assert_in_delta 60, travel_evidence["elapsed_seconds"], 1
      assert_equal event.risk_score, event.metadata.dig("risk_assessment", "factors").sum { |factor| factor["points"] }
      lock = @user.security_events.find_by!(event_type: "account_locked")
      assert_equal "impossible_travel", lock.metadata["reason"]
      assert_equal event.metadata["risk_assessment"], lock.metadata.dig("additional_context", "risk_assessment")
      assert_equal event.metadata.dig("authentication", "attempt_id"), lock.metadata.dig("additional_context", "authentication_attempt_id")
      get "/devise_restricted"
      assert_response :redirect
    end
  end

  test "chronological history not primary key order selects the travel baseline" do
    latest = history(@ny, 1.minute.ago)
    history(@london, 2.hours.ago)
    event = tracked_event
    assert_equal latest.id, event.metadata.dig("geolocation", "travel", "previous_event_id")
    assert event.geolocation["impossible_travel"]
  end

  test "old successful use of the same IP does not suppress current impossible travel" do
    3.times { |i| history(@london, (i + 1).days.ago) }
    history(@ny, 1.minute.ago)
    event = tracked_event
    assert event.geolocation["impossible_travel"]
    assert_equal 31, event.risk_score
    assert_equal 0, event.metadata.dig("risk_assessment", "trust_discount")
  end

  test "monitor mode records would lock with identical evidence but no mutation" do
    history(@ny, 1.minute.ago)
    Beskar.configuration.monitor_only = true
    login("198.51.100.2")
    assert_response :redirect
    refute @user.reload.access_locked?
    event = @user.security_events.login_successes.order(:created_at).last
    assert_equal true, event.metadata.dig("lock_decision", "would_lock")
    assert_equal false, event.metadata.dig("lock_decision", "enforcement_enabled")
    assert_equal "observe", event.metadata.dig("risk_assessment", "mode")
    assert_equal true, event.metadata.dig("geolocation", "impossible_travel")
    refute @user.security_events.exists?(event_type: "account_locked")
  end

  test "whitelist records would lock without locking the account" do
    history(@ny, 1.minute.ago)
    Beskar.configuration.ip_whitelist = ["198.51.100.2"]
    login("198.51.100.2")
    assert_response :redirect
    refute @user.reload.access_locked?
    event = @user.security_events.login_successes.order(:created_at).last
    assert_equal true, event.metadata.dig("lock_decision", "would_lock")
    assert_equal false, event.metadata.dig("lock_decision", "enforcement_enabled")
  end

  test "bot evidence produces the suspicious device reason actually used by recovery" do
    Beskar.configuration.risk_based_locking[:risk_threshold] = 40
    login("198.51.100.1", user_agent: "curl/8.0")
    assert @user.reload.access_locked?
    event = @user.security_events.find_by!(event_type: "authentication_blocked")
    assert_equal true, event.device_info["bot"]
    assert_equal "suspicious_device", @user.security_events.find_by!(event_type: "account_locked").metadata["reason"]
    assert_includes event.metadata.dig("risk_assessment", "factors").map { |factor| factor["name"] }, "user_agent_bot"
  end

  test "native impossible travel locks use persisted evidence without audit autosave" do
    user = create(:user, password: "password123")
    history(@ny, 1.minute.ago, user: user)
    post "/session", params: {email_address: user.email_address, password: "password123"},
      headers: {"X-Forwarded-For" => "198.51.100.2", "User-Agent" => BROWSER}
    assert_response :forbidden
    assert user.beskar_access_locked?
    assert_empty user.sessions
    assert_equal "impossible_travel", user.security_events.find_by!(event_type: "account_locked").metadata["reason"]
  end

  test "unknown geography and malformed history never manufacture travel" do
    history({country: "Unknown", latitude: "bad", longitude: []}, 1.minute.ago)
    event = tracked_event
    refute event.geolocation["impossible_travel"]
    refute event.geolocation["country_change"]
    assert_equal 1, event.risk_score
  end

  test "geographic pattern helper detects admitted travel instead of invalid association eager loading" do
    history(@ny, 2.minutes.ago)
    history(@london, 1.minute.ago)
    assert @user.suspicious_login_pattern?
  end

  test "numeric and recorded scores use one geolocation snapshot per authentication" do
    Beskar::Services::GeolocationService.any_instance.expects(:locate).with("198.51.100.2").once.returns(@london)
    event = tracked_event
    assert_equal event.risk_score, event.metadata.dig("risk_assessment", "score")
  end

  test "disabled strategy is not reported as an available hypothetical lock" do
    Beskar.configuration.monitor_only = true
    Beskar.configuration.risk_based_locking.merge!(lock_strategy: :none, risk_threshold: 1)
    event = tracked_event
    assert_equal false, event.metadata.dig("lock_decision", "strategy_available")
    assert_equal false, event.metadata.dig("lock_decision", "would_lock")
  end

  test "total cap is explicit and authentication headers are bounded" do
    history(@ny, 1.minute.ago)
    2.times { @user.security_events.create!(event_type: "login_failure", ip_address: "198.51.100.2", risk_score: 10, created_at: 1.minute.ago) }
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.2",
      "HTTP_USER_AGENT" => "curl debug iPhone " + "(" * 600)
    event = @user.track_authentication_event(request, :success)
    assert_equal 100, event.risk_score
    factors = event.metadata.dig("risk_assessment", "factors")
    assert_equal 100, factors.sum { |factor| factor["points"] }
    assert factors.any? { |factor| factor["name"] == "total_cap" && factor["points"].negative? }
    assert_operator event.user_agent.length, :<=, 500
  end

  private

  def login(ip, user_agent: BROWSER)
    post "/devise_users/sign_in", params: {devise_user: {email: @user.email, password: "password123"}},
      headers: {"X-Forwarded-For" => ip, "User-Agent" => user_agent}
  end

  def history(location, time, user: @user)
    user.security_events.create!(event_type: "login_success", ip_address: "198.51.100.2", risk_score: 1, created_at: time,
      metadata: {geolocation: location, authentication: {allowed: true, locked_now: false}})
  end

  def tracked_event
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.2", "HTTP_USER_AGENT" => BROWSER)
    @user.track_authentication_event(request, :success)
  end
end
