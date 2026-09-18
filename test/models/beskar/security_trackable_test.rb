require "test_helper"
require_relative "../../beskar_test_base"

class Beskar::SecurityTrackableTest < BeskarTestBase
  def setup
    super
    @user = create(:devise_user)
    @request = mock_request
  end

  test "should create security event on successful login tracking" do
    initial_count = Beskar::SecurityEvent.count
    event = @user.track_authentication_event(@request, :success)

    assert_security_event_created(event, {
      event_type: "login_success",
      ip_address: @request.ip
    })
    assert_equal initial_count + 1, Beskar::SecurityEvent.count
  end

  test "should create security event on failed login tracking" do
    initial_count = Beskar::SecurityEvent.count
    DeviseUser.track_failed_authentication(@request, :devise_user)

    event = Beskar::SecurityEvent.last
    assert_security_event_created(event, {
      event_type: "login_failure",
      ip_address: @request.ip
    })
    assert_nil event.user
    assert_equal initial_count + 1, Beskar::SecurityEvent.count
  end

  test "should extract security context from request" do
    event = @user.track_authentication_event(@request, :success)

    assert_security_event_created(event)
    assert_not_nil event.metadata["timestamp"]
    refute event.metadata.key?("session_id")
    assert_equal "/test", event.metadata["request_path"]
    assert_not_nil event.metadata["device_info"]
  end

  test "should calculate risk score correctly" do
    event = @user.track_authentication_event(@request, :success)
    assert_security_event_created(event)
    assert_risk_score_in_range(event, 1, 100)
  end

  test "should handle blank user agent" do
    blank_request = mock_request(user_agent: "")
    event = @user.track_authentication_event(blank_request, :success)

    # Should increase risk score for blank user agent
    normal_event = @user.track_authentication_event(@request, :success)

    assert_security_event_created(event)
    assert_security_event_created(normal_event)
    assert event.risk_score > normal_event.risk_score
  end

  test "should detect bot user agents" do
    bot_request = mock_bot_request
    event = @user.track_authentication_event(bot_request, :success)

    # Should increase risk score for bot user agents
    normal_event = @user.track_authentication_event(@request, :success)

    assert_security_event_created(event)
    assert_security_event_created(normal_event)
    assert event.risk_score > normal_event.risk_score
  end

  test "should get recent failed attempts" do
    # Create some failed attempts using factory
    user_with_failures = create(:devise_user, :with_failed_attempts)

    # Create an old attempt that shouldn't be included
    create(:security_event, :login_failure, :old, user: user_with_failures)

    recent_attempts = user_with_failures.recent_failed_attempts(within: 1.hour)
    assert_equal 2, recent_attempts.count
  end

  test "should get recent successful logins" do
    user_with_success = create(:devise_user)

    # Create some successful logins
    2.times do |i|
      create(:security_event, :login_success,
        user: user_with_success,
        created_at: Time.current - i.hours)
    end

    recent_logins = user_with_success.recent_successful_logins(within: 24.hours)
    assert_equal 2, recent_logins.count
  end

  test "should detect suspicious login pattern with rapid attempts" do
    user = create(:devise_user)
    simulate_rapid_attempts(user, 3)

    assert user.suspicious_login_pattern?
  end

  test "should not detect suspicious pattern with normal attempts" do
    user = create(:devise_user)
    # Create only 1 failed attempt
    create(:security_event, :login_failure, user: user, created_at: 1.minute.ago)

    assert_not user.suspicious_login_pattern?
  end

  test "should extract browser info from user agent" do
    chrome_request = mock_request(
      user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    )
    event = @user.track_authentication_event(chrome_request, :success)

    assert_security_event_created(event)
    device_info = event.device_info
    assert_match(/Chrome/, device_info["browser"])
    assert_match(/Windows/, device_info["platform"])
    assert_equal false, device_info["mobile"]
  end

  test "should detect mobile devices" do
    mobile_request = mock_mobile_request
    event = @user.track_authentication_event(mobile_request, :success)

    assert_security_event_created(event)
    device_info = event.device_info
    assert_equal true, device_info["mobile"]
    assert_match(/iOS/, device_info["platform"])
  end

  test "should handle missing request gracefully" do
    # Should not raise error when request is nil
    assert_nothing_raised do
      event = @user.track_authentication_event(nil, :success)
      assert_nil event, "Event should be nil for nil request"
    end
  end

  test "should detect mobile devices correctly" do
    mobile_request = mock_mobile_request
    desktop_request = mock_request

    mobile_event = @user.track_authentication_event(mobile_request, :success)
    desktop_user = create(:devise_user)
    desktop_event = desktop_user.track_authentication_event(desktop_request, :success)

    assert_security_event_created(mobile_event)
    assert_security_event_created(desktop_event)

    mobile_device_info = mobile_event.device_info
    desktop_device_info = desktop_event.device_info

    assert_equal true, mobile_device_info["mobile"]
    assert_equal false, desktop_device_info["mobile"]
  end

  test "should increase risk score for users with recent failed attempts" do
    # Create 2 recent failed attempts to trigger risk score increase
    user_with_failures = create(:devise_user, :with_failed_attempts)
    event = user_with_failures.track_authentication_event(@request, :success)

    # Should have higher risk score due to recent failures
    clean_user = create(:devise_user)
    clean_event = clean_user.track_authentication_event(@request, :success)

    assert_security_event_created(event)
    assert_security_event_created(clean_event)
    assert event.risk_score > clean_event.risk_score
  end

  # Configuration Tests
  test "should respect track_successful_logins configuration" do
    original_config = Beskar.configuration.security_tracking

    # Disable successful login tracking
    Beskar.configure do |config|
      config.security_tracking = original_config.merge(track_successful_logins: false)
    end

    initial_count = Beskar::SecurityEvent.count
    @user.track_authentication_event(@request, :success)

    assert_equal initial_count, Beskar::SecurityEvent.count, "Should not create event when tracking disabled"

    # Re-enable and test
    Beskar.configure do |config|
      config.security_tracking = original_config.merge(track_successful_logins: true)
    end

    @user.track_authentication_event(@request, :success)
    assert_equal initial_count + 1, Beskar::SecurityEvent.count, "Should create event when tracking enabled"

    # Restore original config
    Beskar.configuration.security_tracking = original_config
  end

  test "should respect track_failed_logins configuration" do
    original_config = Beskar.configuration.security_tracking

    # Disable failed login tracking
    Beskar.configure do |config|
      config.security_tracking = original_config.merge(track_failed_logins: false)
    end

    initial_count = Beskar::SecurityEvent.count
    DeviseUser.track_failed_authentication(@request, :devise_user)

    assert_equal initial_count, Beskar::SecurityEvent.count, "Should not create event when tracking disabled"

    # Re-enable and test
    Beskar.configure do |config|
      config.security_tracking = original_config.merge(track_failed_logins: true)
    end

    DeviseUser.track_failed_authentication(@request, :devise_user)
    assert_equal initial_count + 1, Beskar::SecurityEvent.count, "Should create event when tracking enabled"

    # Restore original config
    Beskar.configuration.security_tracking = original_config
  end

  test "should respect auto_analyze_patterns configuration" do
    BeskarAnalysisTestJob.expects(:perform_later).never
    assert_nil @user.analyze_suspicious_patterns_async
    Beskar.configure do |config|
      config.security_tracking.merge!(auto_analyze_patterns: true, analysis_job: "BeskarAnalysisTestJob")
    end
    @user.expects(:analyze_suspicious_patterns_async).once
    event = @user.track_authentication_event(@request, :success)
    assert_equal "login_success", event.event_type
  end

  test "should respect security_tracking enabled configuration" do
    original_config = Beskar.configuration.security_tracking

    # Disable security tracking entirely
    Beskar.configure do |config|
      config.security_tracking = original_config.merge(enabled: false)
    end

    initial_count = Beskar::SecurityEvent.count

    # Both successful and failed login tracking should be disabled
    @user.track_authentication_event(@request, :success)
    DeviseUser.track_failed_authentication(@request, :devise_user)

    assert_equal initial_count, Beskar::SecurityEvent.count, "Should not create events when security tracking disabled"

    # Restore original config
    Beskar.configuration.security_tracking = original_config
  end

  test "configuration helper methods work correctly" do
    original_config = Beskar.configuration.security_tracking

    # Test all enabled (default)
    assert Beskar.configuration.security_tracking_enabled?
    assert Beskar.configuration.track_successful_logins?
    assert Beskar.configuration.track_failed_logins?
    assert_not Beskar.configuration.auto_analyze_patterns?

    # Test disabled
    Beskar.configure do |config|
      config.security_tracking = {
        enabled: false,
        track_successful_logins: true,
        track_failed_logins: true,
        auto_analyze_patterns: true
      }
    end

    assert_not Beskar.configuration.security_tracking_enabled?
    assert_not Beskar.configuration.track_successful_logins?
    assert_not Beskar.configuration.track_failed_logins?
    assert_not Beskar.configuration.auto_analyze_patterns?

    # Restore original config
    Beskar.configuration.security_tracking = original_config
  end
end
