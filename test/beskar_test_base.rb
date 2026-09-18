require "test_helper"
require "ostruct"

class BeskarTestBase < ActiveSupport::TestCase
  # Use transactional tests for better performance
  self.use_transactional_tests = true

  def setup
    # Reset Beskar configuration to defaults before each test
    Beskar.instance_variable_set(:@configuration, TestHelper.configuration)

    # Ensure security tracking is enabled by default for tests
    Beskar.configuration.security_tracking[:enabled] = true
    Beskar.configuration.security_tracking[:track_successful_logins] = true
    Beskar.configuration.security_tracking[:track_failed_logins] = true

    # Mark that configuration has been reset to prevent duplicate reset in parent
    @beskar_config_reset = true

    # Clear cache before each test
    Rails.cache.clear
  end

  def teardown
    # Clean up cache after each test
    Rails.cache.clear
  end

  private

  # Helper method to create a mock request object for testing
  def mock_request(options = {})
    headers = {
      "Accept-Language" => "en-US,en;q=0.9",
      "X-Forwarded-For" => nil,
      "X-Real-IP" => nil
    }.merge(options[:headers] || {})

    OpenStruct.new(
      ip: options[:ip] || "192.168.1.1",
      user_agent: options[:user_agent] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      path: options[:path] || "/test",
      referer: options[:referer] || "http://example.com",
      session: OpenStruct.new(id: options[:session_id] || "test_session_123"),
      headers: headers,
      params: options[:params] || {}
    )
  end

  # Helper method to create a mobile request
  def mock_mobile_request(options = {})
    mobile_options = {
      user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
    }.merge(options)

    mock_request(mobile_options)
  end

  # Helper method to create a bot request
  def mock_bot_request(options = {})
    bot_options = {
      user_agent: "Googlebot/2.1 (+http://www.google.com/bot.html)"
    }.merge(options)

    mock_request(bot_options)
  end

  # Helper method to create a suspicious request
  def mock_suspicious_request(options = {})
    suspicious_options = {
      user_agent: "curl/7.68.0",
      ip: "203.0.113.1"
    }.merge(options)

    mock_request(suspicious_options)
  end

  # Helper to assert security event was created with expected attributes
  def assert_security_event_created(event, expected_attributes = {})
    assert_not_nil event, "Security event should be created"
    assert event.persisted?, "Security event should be persisted"

    expected_attributes.each do |key, value|
      assert_equal value, event.send(key), "Expected #{key} to be #{value}"
    end
  end

  # Helper to create multiple security events for testing patterns
  def create_security_events(count, event_type: "login_failure", user: nil, time_range: 5.minutes)
    events = []
    count.times do |i|
      events << create(:security_event, event_type.to_sym,
        user: user,
        created_at: Time.current - (i * (time_range / count)))
    end
    events
  end

  # Helper to simulate rapid login attempts
  def simulate_rapid_attempts(user, count = 3, ip_address = "192.168.1.1")
    count.times do |i|
      create(:security_event, :login_failure,
        user: user,
        ip_address: ip_address,
        created_at: Time.current - i.minutes)
    end
  end

  # Helper to assert risk score is within expected range
  def assert_risk_score_in_range(event, min_score, max_score)
    assert_not_nil event, "Event should exist"
    assert event.risk_score >= min_score, "Risk score should be at least #{min_score}, got #{event.risk_score}"
    assert event.risk_score <= max_score, "Risk score should be at most #{max_score}, got #{event.risk_score}"
  end
end
