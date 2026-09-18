require "test_helper"
require_relative "../beskar_test_base"

class SecurityTrackingBasicTest < BeskarTestBase
  def setup
    super
    @user = create(:devise_user)
  end

  test "should create security event manually" do
    request_mock = mock_request(
      ip: "192.168.1.100",
      user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )

    assert_difference "Beskar::SecurityEvent.count", 1 do
      @user.track_authentication_event(request_mock, :success)
    end

    event = Beskar::SecurityEvent.last
    assert_security_event_created(event, {
      event_type: "login_success",
      user: @user,
      ip_address: "192.168.1.100"
    })
    assert_not_nil event.metadata
    assert_risk_score_in_range(event, 1, 100)
  end

  test "should track failed login without user" do
    request_mock = mock_suspicious_request(
      ip: "10.0.0.1",
      params: {"devise_user" => {"email" => "wrong@example.com"}}
    )

    assert_difference "Beskar::SecurityEvent.count", 1 do
      DeviseUser.track_failed_authentication(request_mock, :devise_user)
    end

    event = Beskar::SecurityEvent.last
    assert_security_event_created(event, {
      event_type: "login_failure",
      ip_address: "10.0.0.1"
    })
    assert_nil event.user
    assert_equal "[FILTERED]", event.attempted_email
    assert_risk_score_in_range(event, 10, 100)
  end

  test "should calculate different risk scores based on patterns" do
    # Normal login
    normal_request = mock_request(ip: "192.168.1.1")
    normal_event = @user.track_authentication_event(normal_request, :success)

    # Suspicious login (no user agent)
    suspicious_request = mock_suspicious_request(user_agent: "")
    suspicious_event = @user.track_authentication_event(suspicious_request, :success)

    assert_security_event_created(normal_event)
    assert_security_event_created(suspicious_event)
    assert suspicious_event.risk_score > normal_event.risk_score
  end

  test "rate limiter should allow initial requests" do
    result = Beskar::Services::RateLimiter.check_ip_rate_limit("192.168.1.50")

    assert result[:allowed]
    assert_equal 10, result[:limit]
    assert_equal 0, result[:count]
    assert_equal 10, result[:remaining]
  end

  test "rate limiter should block after limit exceeded" do
    ip = "192.168.1.51"
    request = mock_request(ip: ip)
    10.times do
      Beskar::Services::RateLimiter.check_authentication_attempt(request, :failure)
    end

    result = Beskar::Services::RateLimiter.check_ip_rate_limit(ip)
    assert_equal false, result[:allowed]
    assert_equal "rate_limit_exceeded", result[:reason]
    assert result[:retry_after] > 0
  end

  test "rate limiter should handle account-based limiting" do
    result = Beskar::Services::RateLimiter.check_account_rate_limit(@user)

    assert result[:allowed]
    assert_equal 5, result[:limit] # Account limit is 5
    assert_equal 0, result[:count]
  end

  test "should detect device information from user agent" do
    chrome_request = mock_request(
      user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    )

    event = @user.track_authentication_event(chrome_request, :success)
    device_info = event.device_info

    assert_match(/Chrome/, device_info["browser"])
    assert_match(/Windows/, device_info["platform"])
    assert_equal false, device_info["mobile"]
  end

  test "should detect mobile devices" do
    mobile_request = mock_mobile_request

    event = @user.track_authentication_event(mobile_request, :success)
    device_info = event.device_info

    assert_equal true, device_info["mobile"]
    assert_match(/iOS/, device_info["platform"])
  end

  test "should detect suspicious login patterns" do
    user = create(:devise_user)
    simulate_rapid_attempts(user, 3)

    assert user.suspicious_login_pattern?
  end

  test "should get recent failed attempts" do
    user_with_failures = create(:devise_user)

    # Create some recent failed attempts using helper
    2.times do |i|
      create(:security_event, :login_failure,
        user: user_with_failures,
        created_at: Time.current - (i * 5).minutes)
    end

    # Create an old attempt that shouldn't be included
    create(:security_event, :login_failure, :old, user: user_with_failures)

    recent_attempts = user_with_failures.recent_failed_attempts(within: 1.hour)
    assert_equal 2, recent_attempts.count
  end

  test "rate limiter instance methods should work" do
    rate_limiter = Beskar::Services::RateLimiter.new("192.168.1.200", @user)

    assert rate_limiter.allowed?
    assert_equal 5, rate_limiter.attempts_remaining # Account limit is more restrictive
    assert_equal 0, rate_limiter.time_until_reset
  end

  test "should detect attack patterns" do
    user = create(:devise_user)

    # Create distributed attack pattern (same user, different IPs)
    ["192.168.1.1", "192.168.1.2"].each_with_index do |ip, i|
      create(:security_event, :login_failure,
        user: user,
        ip_address: ip,
        created_at: Time.current - (i * 60),
        metadata: {"attempted_email" => user.email})
    end

    rate_limiter = Beskar::Services::RateLimiter.new("192.168.1.1", user)
    assert_equal :distributed_single_account, rate_limiter.attack_pattern_type
  end

  test "security event scopes should work" do
    # Create various types of events using factories
    success_event = create(:security_event, :login_success, risk_score: 10)
    failure_event = create(:security_event, :login_failure, risk_score: 30)
    high_risk_event = create(:security_event, :login_success, :high_risk)

    successes = Beskar::SecurityEvent.login_successes
    failures = Beskar::SecurityEvent.login_failures
    high_risk = Beskar::SecurityEvent.high_risk

    assert_includes successes, success_event
    assert_includes successes, high_risk_event
    assert_includes failures, failure_event
    assert_includes high_risk, high_risk_event

    assert_equal 2, successes.count
    assert_equal 1, failures.count
    assert_equal 1, high_risk.count
  end
end
