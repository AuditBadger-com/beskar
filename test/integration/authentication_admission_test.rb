require "test_helper"

class AuthenticationAdmissionTest < ActionDispatch::IntegrationTest
  setup do
    @devise_user = create(:devise_user, email: "admission@example.com", password: "password123")
    @native_user = create(:user, email_address: "native@example.com", password: "password123")
    @limiter = Beskar::Services::RateLimiter
    Beskar.configuration.rate_limiting[:ip_attempts][:limit] = 100
    Beskar.configuration.risk_based_locking.merge!(enabled: false, notify_user: false)
  end

  test "distributed failed Devise attempts enforce account admission before password verification" do
    Beskar.configuration.rate_limiting[:account_attempts][:limit] = 2
    2.times do |i|
      devise_login(password: "wrong", ip: "198.51.100.#{i + 1}")
      assert_response :unprocessable_content
    end
    DeviseUser.any_instance.expects(:valid_password?).never
    devise_login(ip: "198.51.100.3")
    assert_response :too_many_requests
    assert_equal 2, @limiter.check_account_rate_limit(@devise_user)[:count]
    assert_equal 2, @devise_user.security_events.login_failures.count
    assert_equal "authentication_blocked", Beskar::SecurityEvent.last.event_type
    get "/devise_restricted"
    assert_response :redirect
  end

  test "global limit blocks a different account and IP before checking credentials" do
    Beskar.configuration.rate_limiting[:global_attempts][:enabled] = true
    Beskar.configuration.rate_limiting[:global_attempts][:limit] = 1
    devise_login(password: "wrong", ip: "198.51.100.1")
    assert_response :unprocessable_content
    User.expects(:authenticate_by).never
    native_login(ip: "198.51.100.2")
    assert_response :too_many_requests
    assert_equal 0, @native_user.sessions.count
  end

  test "nonexistent account identities are normalized and limited without storing plaintext keys" do
    Beskar.configuration.rate_limiting[:account_attempts][:limit] = 1
    devise_login(email: "unknown@example.com", password: "wrong", ip: "198.51.100.1")
    assert_response :unprocessable_content
    devise_login(email: " UNKNOWN@example.com ", ip: "198.51.100.2")
    assert_response :too_many_requests
    refute Beskar::SecurityState.pluck(:key).any? { |key| key.include?("unknown@example.com") }
  end

  test "protected page visits without credentials create no attempts or failures" do
    assert_no_difference ["Beskar::SecurityEvent.count", "Beskar::SecurityState.count"] do
      3.times do
        get "/devise_restricted"
        assert_response :redirect
      end
    end
    assert_equal 0, @limiter.check_global_rate_limit[:count]
  end

  test "audit tracking switches cannot disable admission enforcement" do
    Beskar.configuration.security_tracking[:enabled] = false
    Beskar.configuration.rate_limiting[:account_attempts][:limit] = 1
    assert_no_difference "Beskar::SecurityEvent.count" do
      devise_login(password: "wrong", ip: "198.51.100.1")
      assert_response :unprocessable_content
      devise_login(ip: "198.51.100.2")
      assert_response :too_many_requests
    end
  end

  test "Warden success consumes an admission only once and fetch consumes nothing" do
    devise_login
    assert_response :redirect
    assert_equal 1, @limiter.check_account_rate_limit(@devise_user)[:count]
    get "/devise_restricted"
    assert_response :success
    assert_equal 1, @limiter.check_account_rate_limit(@devise_user)[:count]
    assert_equal 1, @devise_user.security_events.login_successes.count
  end

  test "low risk Warden sign in works with immediate signout enabled" do
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 100, immediate_signout: true)
    devise_login
    assert_response :redirect
    get "/devise_restricted"
    assert_response :success
    refute @devise_user.reload.access_locked?
  end

  test "high risk Warden sign in is rejected even when every audit write is disabled" do
    Beskar.configuration.security_tracking[:enabled] = false
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1, immediate_signout: true, log_lock_events: false)
    assert_no_difference "Beskar::SecurityEvent.count" do
      devise_login
    end
    assert @devise_user.reload.access_locked?
    get "/devise_restricted"
    assert_response :redirect
  end

  test "audit persistence failure cannot prevent a high risk account lock or signout" do
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1, immediate_signout: true)
    Beskar::SecurityEvent.any_instance.stubs(:save).raises(ActiveRecord::StatementInvalid, "audit unavailable")
    Beskar::SecurityEvent.any_instance.stubs(:save!).raises(ActiveRecord::StatementInvalid, "audit unavailable")
    devise_login
    assert @devise_user.reload.access_locked?
    get "/devise_restricted"
    assert_response :redirect
  end

  test "ordinary audit failure does not prevent an allowed login" do
    Beskar::SecurityEvent.any_instance.stubs(:save).raises(ActiveRecord::StatementInvalid, "audit unavailable")
    devise_login
    assert_response :redirect
    get "/devise_restricted"
    assert_response :success
    assert_equal 1, @limiter.check_account_rate_limit(@devise_user)[:count]
  end

  test "state failures reject authentication with 503 instead of admitting a session" do
    Beskar::SecurityState.stubs(:mutate).raises(ActiveRecord::ConnectionNotEstablished)
    DeviseUser.any_instance.expects(:valid_password?).never
    devise_login
    assert_response :service_unavailable
    User.expects(:authenticate_by).never
    native_login
    assert_response :service_unavailable
  end

  test "risk assessment failures revoke the newly set Warden scope" do
    Beskar.configuration.risk_based_locking[:enabled] = true
    DeviseUser.any_instance.stubs(:assess_authentication_risk).raises("risk unavailable")
    devise_login
    assert_response :service_unavailable
    get "/devise_restricted"
    assert_response :redirect
  end

  test "unsupported lock strategy cannot silently admit users when validation is bypassed" do
    Beskar.configuration.risk_based_locking.merge!(enabled: true, lock_strategy: :custom)
    devise_login
    assert_response :service_unavailable
    get "/devise_restricted"
    assert_response :redirect
    native_login
    assert_response :service_unavailable
    assert_empty @native_user.sessions
  end

  test "optional audit enrichment failure does not reject authentication" do
    DeviseUser.any_instance.stubs(:assess_authentication_risk).raises("enrichment unavailable")
    devise_login
    assert_response :redirect
    get "/devise_restricted"
    assert_response :success
  end

  test "Warden signout leaves an unrelated scope authenticated" do
    env = Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "198.51.100.50", "rack.session" => {})
    manager = Warden::Manager.new(->(_) { [200, {}, []] })
    auth = Warden::Proxy.new(env, manager)
    other = create(:devise_user)
    auth.set_user(other, scope: :other, run_callbacks: false)
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1, immediate_signout: true)
    result = catch(:warden) { auth.set_user(@devise_user, scope: :devise_user) }
    assert_equal :devise_user, result[:scope]
    assert_nil auth.user(:devise_user)
    assert_equal other, auth.user(:other)
  end

  test "monitor mode and whitelist prevent both native and Devise automatic locks" do
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1, immediate_signout: true)
    Beskar.configuration.monitor_only = true
    devise_login
    assert_response :redirect
    refute @devise_user.reload.access_locked?
    native_login
    assert_response :redirect
    refute @native_user.beskar_access_locked?
    assert_equal 1, @native_user.sessions.count

    Beskar.configuration.monitor_only = false
    Beskar.configuration.ip_whitelist = ["198.51.100.90"]
    locker = Beskar::Services::AccountLocker.new(@devise_user, risk_score: 100, metadata: {"ip_address" => "198.51.100.90"})
    refute locker.lock!
    refute @devise_user.reload.access_locked?
    native_login(ip: "198.51.100.90")
    assert_response :redirect
    refute @native_user.beskar_access_locked?
    assert_equal 2, @native_user.sessions.count
    assert_equal 0, @limiter.check_global_rate_limit[:count]
  end

  test "native high risk locks revoke every session and do not create a replacement" do
    2.times { @native_user.sessions.create! }
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1)
    native_login
    assert_response :forbidden
    assert @native_user.beskar_access_locked?
    assert_empty @native_user.sessions.reload
    assert_equal 0, @native_user.security_events.login_successes.count
    assert @native_user.security_events.exists?(event_type: "authentication_blocked")
    get "/user_restricted"
    assert_response :redirect
  end

  test "native finite locks expire and nil unlock duration requires explicit unlock" do
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1, auto_unlock_time: 1.minute)
    native_login
    assert_response :forbidden
    travel 61.seconds do
      Beskar.configuration.risk_based_locking[:risk_threshold] = 100
      native_login
      assert_response :redirect
      refute @native_user.beskar_access_locked?
    end
    Beskar.configuration.risk_based_locking[:auto_unlock_time] = nil
    locker = Beskar::Services::AccountLocker.new(@native_user, risk_score: 100)
    # Clear the finite lock whose original deadline is restored after travel.
    locker.unlock!
    assert locker.lock!
    travel 2.days do
      assert @native_user.beskar_access_locked?
    end
    assert locker.unlock!
    refute @native_user.beskar_access_locked?
  end

  test "native session creation rechecks locks after risk assessment" do
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.50")
    Beskar::Services::NativeAccountLock.lock!(@native_user, duration: 1.hour)
    called = false
    refute @native_user.with_beskar_session(request) { called = true }
    refute called
    assert_empty @native_user.sessions
  end

  test "native admission still rejects account limits with audit logging disabled" do
    Beskar.configuration.security_tracking[:enabled] = false
    Beskar.configuration.rate_limiting[:account_attempts][:limit] = 1
    native_login(password: "wrong", ip: "198.51.100.1")
    assert_response :redirect
    User.expects(:authenticate_by).never
    native_login(ip: "198.51.100.2")
    assert_response :too_many_requests
    assert_empty @native_user.sessions
  end

  test "native high risk enforcement does not depend on any audit writes" do
    Beskar.configuration.security_tracking[:enabled] = false
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1, log_lock_events: false)
    @native_user.sessions.create!
    assert_no_difference "Beskar::SecurityEvent.count" do
      native_login
    end
    assert_response :forbidden
    assert @native_user.beskar_access_locked?
    assert_empty @native_user.sessions.reload
  end

  test "native lock authority survives a failing session destruction callback" do
    session = @native_user.sessions.create!
    Session.any_instance.stubs(:destroy).raises(ActiveRecord::RecordNotDestroyed)
    assert Beskar::Services::NativeAccountLock.lock!(@native_user, duration: 1.hour)
    assert Session.exists?(session.id)
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.1")
    refute @native_user.beskar_access_allowed?(request)
    refute @native_user.with_beskar_session(request) { flunk "Must not create a replacement session" }
    travel 2.days do
      assert @native_user.beskar_access_locked?, "Failed cleanup must prevent automatic unlock"
    end
    assert_raises(ActiveRecord::RecordNotDestroyed) { Beskar::Services::NativeAccountLock.unlock!(@native_user) }
    assert @native_user.beskar_access_locked?
    Session.any_instance.unstub(:destroy)
    assert Beskar::Services::NativeAccountLock.unlock!(@native_user)
    refute @native_user.beskar_access_locked?
    refute Session.exists?(session.id)
  end

  test "aborted native session destruction also requires cleanup before unlocking" do
    session = @native_user.sessions.create!
    Session.any_instance.stubs(:destroy).returns(false)
    assert Beskar::Services::NativeAccountLock.lock!(@native_user, duration: 1.minute)
    travel 2.minutes do
      assert @native_user.beskar_access_locked?
    end
    assert Session.exists?(session.id)
    assert_raises(ActiveRecord::RecordNotDestroyed) { Beskar::Services::NativeAccountLock.unlock!(@native_user) }
  end

  test "Devise lock persistence failures do not admit the new scope" do
    Beskar.configuration.risk_based_locking.merge!(enabled: true, risk_threshold: 1, immediate_signout: true)
    DeviseUser.any_instance.stubs(:lock_access!).returns(false)
    devise_login
    assert_response :service_unavailable
    get "/devise_restricted"
    assert_response :redirect
  end

  test "Devise scope aliases use the configured mapping rather than constantizing the scope" do
    mapping = mock("mapping")
    mapping.stubs(:to).returns(DeviseUser)
    Devise.stubs(:mappings).returns(administrator: mapping)
    assert_equal DeviseUser, Beskar.configuration.model_class_for_scope(:administrator)
  end

  test "HTTP Basic password authentication is admitted and records its target account" do
    DeviseUser.stubs(:http_authenticatable?).returns(true)
    Beskar.configuration.rate_limiting[:account_attempts][:limit] = 1
    authorization = ActionController::HttpAuthentication::Basic.encode_credentials(@devise_user.email, "wrong")
    get "/devise_restricted", headers: {"Authorization" => authorization, "X-Forwarded-For" => "198.51.100.1"}
    assert_equal 1, @limiter.check_account_rate_limit(@devise_user)[:count]
    assert_equal "[FILTERED]", Beskar::SecurityEvent.last.attempted_email
    get "/devise_restricted", headers: {"Authorization" => authorization, "X-Forwarded-For" => "198.51.100.2"}
    assert_response :too_many_requests
  end

  test "auth audit context excludes session secrets and referrer credentials and queries" do
    post "/devise_users/sign_in", params: {devise_user: {email: @devise_user.email, password: "wrong"}},
      headers: {"Referer" => "https://name:secret@example.com/login?token=secret-query-value#secret"}
    event = Beskar::SecurityEvent.last
    assert_equal "https://example.com/login", event.metadata["referer"]
    refute event.metadata.key?("session_id")
    assert_equal "/devise_users/sign_in", event.metadata["request_path"]
    refute_includes event.metadata.to_json, "secret-query-value"
    refute_includes event.metadata.to_json, "secret"
  end

  test "emergency reset respects monitor and whitelist policy" do
    Beskar.configuration.emergency_password_reset[:enabled] = true
    event = @native_user.security_events.create!(event_type: "account_locked", ip_address: "198.51.100.90", risk_score: 100)
    original = @native_user.password_digest
    Beskar.configuration.monitor_only = true
    refute @native_user.perform_emergency_password_reset(event, :high_risk_authentication)
    Beskar.configuration.monitor_only = false
    Beskar.configuration.ip_whitelist = [event.ip_address]
    refute @native_user.perform_emergency_password_reset(event, :high_risk_authentication)
    assert_equal original, @native_user.reload.password_digest
  end

  test "emergency reset rolls back password and manual lock if its recovery audit fails" do
    Beskar.configuration.emergency_password_reset.merge!(enabled: true, require_manual_unlock: true)
    event = @native_user.security_events.create!(event_type: "account_locked", ip_address: "198.51.100.90", risk_score: 100)
    original = @native_user.password_digest
    session = @native_user.sessions.create!
    Beskar::SecurityEvent.any_instance.stubs(:save!).raises(ActiveRecord::StatementInvalid, "audit unavailable")
    refute @native_user.perform_emergency_password_reset(event, :high_risk_authentication)
    assert_equal original, @native_user.reload.password_digest
    refute @native_user.beskar_access_locked?
    assert Session.exists?(session.id), "Recovery audit failure must roll back session deletion too"
  end

  test "emergency reset requires manual unlock when configured" do
    Beskar.configuration.emergency_password_reset.merge!(enabled: true, require_manual_unlock: true)
    event = @native_user.security_events.create!(event_type: "account_locked", ip_address: "198.51.100.90", risk_score: 100)
    @native_user.sessions.create!
    assert @native_user.perform_emergency_password_reset(event, :high_risk_authentication)
    assert_empty @native_user.sessions.reload
    travel 2.days do
      assert @native_user.beskar_access_locked?
    end
    Beskar::Services::AccountLocker.new(@native_user, risk_score: 0).unlock!
    refute @native_user.beskar_access_locked?
  end

  test "false travel flags and duplicate success evidence do not inflate reset thresholds" do
    Beskar.configuration.emergency_password_reset.merge!(enabled: true, impossible_travel_threshold: 2)
    3.times do
      @native_user.security_events.create!(event_type: "account_locked", ip_address: "198.51.100.90", risk_score: 50,
        metadata: {geolocation: {impossible_travel: false}})
    end
    event = @native_user.security_events.last
    refute @native_user.should_reset_password?(event, :impossible_travel)
    @native_user.security_events.create!(event_type: "login_success", ip_address: "198.51.100.90", risk_score: 100,
      metadata: {geolocation: {impossible_travel: true}})
    @native_user.security_events.create!(event_type: "account_locked", ip_address: "198.51.100.90", risk_score: 100,
      metadata: {additional_context: {geolocation: {impossible_travel: true}}})
    refute @native_user.should_reset_password?(event, :impossible_travel)
    @native_user.security_events.create!(event_type: "account_locked", ip_address: "198.51.100.90", risk_score: 100,
      metadata: {reason: "impossible_travel"})
    assert @native_user.should_reset_password?(event, :impossible_travel)
  end

  test "both authentication paths invoke configured analysis after successful admission" do
    enable_background_analysis
    DeviseUser.any_instance.expects(:analyze_suspicious_patterns_async).once
    User.any_instance.expects(:analyze_suspicious_patterns_async).once
    devise_login
    assert_response :redirect
    native_login
    assert_response :redirect
    assert_equal 1, @native_user.sessions.count
  end

  test "native final session denial does not invoke analysis" do
    enable_background_analysis
    User.any_instance.stubs(:with_beskar_session).returns(false)
    User.any_instance.expects(:analyze_suspicious_patterns_async).never
    native_login
    assert_response :forbidden
    assert_empty @native_user.sessions
    assert_equal "authentication_blocked", @native_user.security_events.last.event_type
  end

  test "disabled successful tracking and failed credentials do not invoke analysis" do
    enable_background_analysis
    User.any_instance.expects(:analyze_suspicious_patterns_async).never
    DeviseUser.any_instance.expects(:analyze_suspicious_patterns_async).never
    native_login(password: "wrong")
    assert_response :redirect
    devise_login(password: "wrong")
    assert_response :unprocessable_content
    Beskar.configure { |config| config.security_tracking[:track_successful_logins] = false }
    native_login
    assert_response :redirect
    devise_login
    assert_response :redirect
  end

  private

  def enable_background_analysis
    Beskar.configure { |config| config.security_tracking.merge!(auto_analyze_patterns: true, analysis_job: "BeskarAnalysisTestJob") }
  end

  def devise_login(email: @devise_user.email, password: "password123", ip: "198.51.100.50")
    post "/devise_users/sign_in", params: {devise_user: {email: email, password: password}}, headers: {"X-Forwarded-For" => ip}
  end

  def native_login(password: "password123", ip: "198.51.100.60")
    post "/session", params: {email_address: @native_user.email_address, password: password}, headers: {"X-Forwarded-For" => ip}
  end
end
