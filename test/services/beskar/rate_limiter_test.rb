require "test_helper"
require_relative "../../beskar_test_base"

class Beskar::Services::RateLimiterTest < BeskarTestBase
  def setup
    super
    Beskar.configuration.rate_limiting[:global_attempts][:enabled] = true
    @request = mock_request
    @user = create(:devise_user)
    @rate_limiter = Beskar::Services::RateLimiter
  end

  test "should allow authentication attempts under IP limit" do
    result = @rate_limiter.check_ip_rate_limit("192.168.1.1")

    assert result[:allowed]
    assert_equal 0, result[:count]
    assert_equal 10, result[:limit] # Default limit
    assert_equal 10, result[:remaining]
  end

  test "should block authentication attempts over IP limit" do
    ip = "192.168.1.2"

    # Make 10 attempts (the default limit)
    10.times do
      @rate_limiter.send(:record_attempt, ip, :failure, nil)
    end

    result = @rate_limiter.check_ip_rate_limit(ip)
    assert_not result[:allowed]
    assert_equal "rate_limit_exceeded", result[:reason]
    assert result[:retry_after] > 0
  end

  test "should allow authentication attempts under account limit" do
    result = @rate_limiter.check_account_rate_limit(@user)

    assert result[:allowed]
    assert_equal 0, result[:count]
    assert_equal 5, result[:limit] # Default account limit
    assert_equal 5, result[:remaining]
  end

  test "should block authentication attempts over account limit" do
    # Make 5 attempts (the default account limit)
    5.times do
      @rate_limiter.send(:record_attempt, "192.168.1.1", :failure, @user)
    end

    result = @rate_limiter.check_account_rate_limit(@user)
    assert_not result[:allowed]
    assert_equal "rate_limit_exceeded", result[:reason]
  end

  test "should allow requests under global limit" do
    result = @rate_limiter.check_global_rate_limit

    assert result[:allowed]
    assert_equal 100, result[:limit] # Default global limit
  end

  test "should use exponential backoff for IP blocking" do
    ip = "192.168.1.3"
    Beskar.configuration.rate_limiting[:ip_attempts][:period] = 1.second

    # First block - should have minimal retry_after
    10.times do
      @rate_limiter.send(:record_attempt, ip, :failure, nil)
    end

    request = mock_request(ip: ip)
    first_result = @rate_limiter.check_authentication_attempt(request, :failure)
    first_retry_after = first_result[:retry_after]

    # Second block - should have longer retry_after
    second_result = @rate_limiter.check_authentication_attempt(request, :failure)
    second_retry_after = second_result[:retry_after]

    assert second_retry_after > first_retry_after
  end

  test "should reset rate limits correctly" do
    ip = "192.168.1.4"

    # Make attempts to trigger rate limiting
    10.times do
      @rate_limiter.send(:record_attempt, ip, :failure, nil)
    end

    # Verify it's blocked
    result = @rate_limiter.check_ip_rate_limit(ip)
    assert_not result[:allowed]

    # Reset the limit
    @rate_limiter.reset_rate_limit(ip_address: ip)

    # Should be allowed again
    result = @rate_limiter.check_ip_rate_limit(ip)
    assert result[:allowed]
  end

  test "should check authentication attempt with all limits" do
    result = @rate_limiter.check_authentication_attempt(@request, :failure, @user)

    assert result[:allowed]
    assert result.key?(:count)
    assert result.key?(:limit)
  end

  test "should return most restrictive result" do
    ip = "192.168.1.5"

    # Fill up IP limit
    10.times do
      @rate_limiter.send(:record_attempt, ip, :failure, nil)
    end

    request = mock_request(ip: ip)
    result = @rate_limiter.check_authentication_attempt(request, :failure, @user)

    # Should be blocked due to IP limit even though account limit is fine
    assert_not result[:allowed]
  end

  test "should detect rate limiting status" do
    ip = "192.168.1.6"
    request = mock_request(ip: ip)

    # Should not be rate limited initially
    assert_not @rate_limiter.is_rate_limited?(request, @user)

    # Fill up the limit
    10.times do
      @rate_limiter.send(:record_attempt, ip, :failure, @user)
    end

    # Should be rate limited now
    assert @rate_limiter.is_rate_limited?(request, @user)
  end

  test "should calculate time until allowed" do
    ip = "192.168.1.7"
    request = mock_request(ip: ip)

    # Initially should be 0
    assert_equal 0, @rate_limiter.time_until_allowed(request, @user)

    # Fill up the limit
    10.times do
      @rate_limiter.send(:record_attempt, ip, :failure, @user)
    end

    # Should have a positive time until allowed
    time_until = @rate_limiter.time_until_allowed(request, @user)
    assert time_until > 0
  end

  test "should not record attempts for check operations" do
    # Make a check operation (shouldn't record)
    @rate_limiter.check_authentication_attempt(@request, :check, @user)

    # Count should still be 0
    ip_result = @rate_limiter.check_ip_rate_limit(@request.ip)
    assert_equal 0, ip_result[:count]
  end

  test "should handle sliding window correctly" do
    ip = "192.168.1.9"

    # Make attempts at different times
    travel_to 2.hours.ago do
      5.times { @rate_limiter.send(:record_attempt, ip, :failure, nil) }
    end

    travel_to 30.minutes.ago do
      3.times { @rate_limiter.send(:record_attempt, ip, :failure, nil) }
    end

    # Current window should only include recent attempts
    result = @rate_limiter.check_ip_rate_limit(ip)
    assert_equal 3, result[:count] # Only the recent 3 attempts
  end

  test "instance methods should work correctly" do
    rate_limiter = Beskar::Services::RateLimiter.new("192.168.1.10", @user)

    assert rate_limiter.allowed?
    assert_equal 5, rate_limiter.attempts_remaining # Account limit is more restrictive
    assert_equal 0, rate_limiter.time_until_reset
  end

  test "should detect suspicious patterns" do
    user = DeviseUser.create!(email: "suspicious#{Time.current.to_f}@example.com", password: "password123")

    # Create rapid failed attempts for pattern detection
    3.times do |i|
      user.security_events.create!(
        event_type: "login_failure",
        ip_address: "192.168.1.1",
        user_agent: "Test Agent",
        risk_score: 25,
        created_at: Time.current - i.minutes,
        metadata: {attempted_email: user.email}
      )
    end

    rate_limiter = Beskar::Services::RateLimiter.new("192.168.1.1", user)
    assert rate_limiter.suspicious_pattern?
  end

  test "should detect attack pattern types" do
    user = DeviseUser.create!(email: "attack#{Time.current.to_f}@example.com", password: "password123")

    # Create distributed attack pattern (same user, different IPs)
    ["192.168.1.1", "192.168.1.2"].each_with_index do |ip, i|
      user.security_events.create!(
        event_type: "login_failure",
        ip_address: ip,
        user_agent: "Test Agent",
        risk_score: 25,
        created_at: Time.current - (i * 60),
        metadata: {attempted_email: user.email}
      )
    end

    rate_limiter = Beskar::Services::RateLimiter.new("192.168.1.1", user)
    assert_equal :distributed_single_account, rate_limiter.attack_pattern_type
  end

  test "should detect brute force single account pattern" do
    user = DeviseUser.create!(email: "brute#{Time.current.to_f}@example.com", password: "password123")

    # Create single IP, single account attempts
    3.times do |i|
      user.security_events.create!(
        event_type: "login_failure",
        ip_address: "192.168.1.1",
        user_agent: "Test Agent",
        risk_score: 25,
        created_at: Time.current - (i * 60),
        metadata: {attempted_email: user.email}
      )
    end

    rate_limiter = Beskar::Services::RateLimiter.new("192.168.1.1", user)
    assert_equal :brute_force_single_account, rate_limiter.attack_pattern_type
  end

  test "should handle custom configuration" do
    # Test with custom rate limiting config
    original_config = Beskar.configuration.rate_limiting

    Beskar.configure do |config|
      config.rate_limiting = {
        ip_attempts: {
          limit: 5,
          period: 30.minutes,
          exponential_backoff: false
        }
      }
    end

    result = @rate_limiter.check_ip_rate_limit("192.168.1.11")
    assert_equal 5, result[:limit]

    # Restore original config
    Beskar.configuration.rate_limiting = original_config
  end

  private

  def mock_request(options = {})
    OpenStruct.new(
      ip: options[:ip] || "192.168.1.1",
      user_agent: options[:user_agent] || "Mozilla/5.0 Test Browser",
      path: options[:path] || "/test",
      session: OpenStruct.new(id: "test_session_123"),
      params: options[:params] || {}
    )
  end
end
