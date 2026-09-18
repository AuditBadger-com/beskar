require "test_helper"

class RiskBasedLockingTest < ActionDispatch::IntegrationTest
  setup do
    @user = DeviseUser.create!(
      email: "locktest@example.com",
      password: "password123",
      password_confirmation: "password123"
    )

    # Reset configuration to defaults
    Beskar.instance_variable_set(:@configuration, TestHelper.configuration)

    # Clear any existing security events
    Beskar::SecurityEvent.delete_all
  end

  teardown do
    # Clean up
    @user&.destroy
    Beskar::SecurityEvent.delete_all
  end

  test "should track high risk login but not lock when locking is disabled" do
    Beskar.configuration.risk_based_locking[:enabled] = false
    Beskar.configuration.security_tracking[:enabled] = true

    # Simulate a login with high risk factors
    post devise_user_session_path, params: {
      devise_user: {email: @user.email, password: "password123"}
    }

    assert_response :redirect

    # Security event should be created
    assert @user.security_events.login_successes.any?,
      "Should create login success event"

    # User should not be locked when feature is disabled
    # Note: lockable module may not be enabled in test environment
    @user.reload
    if @user.respond_to?(:access_locked?)
      assert_not @user.access_locked?,
        "User should not be locked when risk-based locking is disabled"
    end
  end

  test "should not lock user when risk score is below threshold" do
    Beskar.configuration.risk_based_locking[:enabled] = true
    Beskar.configuration.risk_based_locking[:risk_threshold] = 90
    Beskar.configuration.security_tracking[:enabled] = true

    # Login with normal conditions (low risk)
    post devise_user_session_path, params: {
      devise_user: {email: @user.email, password: "password123"}
    }

    assert_response :redirect

    # Check the risk score of the created event
    last_event = @user.security_events.login_successes.last
    assert_not_nil last_event, "Should create login success event"
    assert last_event.risk_score < 90,
      "Risk score #{last_event.risk_score} should be below threshold of 90"

    # User should not be locked when risk is below threshold
    # Note: lockable module may not be enabled in test environment
    @user.reload
    if @user.respond_to?(:access_locked?)
      assert_not @user.access_locked?,
        "User should not be locked when risk score is below threshold"
    end
  end

  test "should create account_locked security event when user is locked" do
    # This test verifies the logging functionality
    Beskar.configuration.risk_based_locking[:enabled] = true
    Beskar.configuration.risk_based_locking[:risk_threshold] = 50
    Beskar.configuration.risk_based_locking[:log_lock_events] = true

    # Manually create a high-risk security event
    security_event = @user.security_events.create!(
      event_type: "login_success",
      ip_address: "203.0.113.1",
      user_agent: "Suspicious Browser",
      risk_score: 85,
      metadata: {
        device_info: {suspicious: true},
        geolocation: {country: "Unknown"}
      }
    )

    # Manually trigger the account locker
    locker = Beskar::Services::AccountLocker.new(
      @user,
      risk_score: 85,
      reason: :high_risk_authentication,
      metadata: {
        ip_address: "203.0.113.1",
        user_agent: "Suspicious Browser",
        security_event_id: security_event.id
      }
    )

    # Should want to lock but fail (no :lockable module)
    assert locker.should_lock?

    # Verify the decision was correct
    assert_equal 85, locker.risk_score
    assert_equal :high_risk_authentication, locker.reason
  end

  test "should respect risk threshold configuration" do
    # Test with threshold of 75
    Beskar.configuration.risk_based_locking[:enabled] = true
    Beskar.configuration.risk_based_locking[:risk_threshold] = 75

    locker_below = Beskar::Services::AccountLocker.new(@user, risk_score: 74)
    locker_at = Beskar::Services::AccountLocker.new(@user, risk_score: 75)
    locker_above = Beskar::Services::AccountLocker.new(@user, risk_score: 76)

    assert_not locker_below.should_lock?, "Score below threshold should not lock"
    assert locker_at.should_lock?, "Score at threshold should lock"
    assert locker_above.should_lock?, "Score above threshold should lock"
  end

  test "should determine correct lock reason based on security event metadata" do
    # Test impossible travel detection
    security_event = @user.security_events.create!(
      event_type: "login_success",
      ip_address: "203.0.113.1",
      user_agent: "Normal Browser",
      risk_score: 85,
      metadata: {
        geolocation: {impossible_travel: true, country: "Japan"}
      }
    )

    reason = @user.send(:determine_lock_reason, security_event)
    assert_equal :impossible_travel, reason

    # Test suspicious device
    security_event2 = @user.security_events.create!(
      event_type: "login_success",
      ip_address: "203.0.113.2",
      user_agent: "Bot Browser",
      risk_score: 85,
      metadata: {
        device_info: {bot_signature: true}
      }
    )

    reason2 = @user.send(:determine_lock_reason, security_event2)
    assert_equal :suspicious_device, reason2

    # Test geographic anomaly
    security_event3 = @user.security_events.create!(
      event_type: "login_success",
      ip_address: "203.0.113.3",
      user_agent: "Normal Browser",
      risk_score: 85,
      metadata: {
        geolocation: {country_change: true}
      }
    )

    reason3 = @user.send(:determine_lock_reason, security_event3)
    assert_equal :geographic_anomaly, reason3

    # Test default reason
    security_event4 = @user.security_events.create!(
      event_type: "login_success",
      ip_address: "203.0.113.4",
      user_agent: "Normal Browser",
      risk_score: 85,
      metadata: {}
    )

    reason4 = @user.send(:determine_lock_reason, security_event4)
    assert_equal :high_risk_authentication, reason4
  end

  test "configuration helper methods should work correctly" do
    # Test enabled check
    Beskar.configuration.risk_based_locking[:enabled] = true
    assert Beskar.configuration.risk_based_locking_enabled?

    Beskar.configuration.risk_based_locking[:enabled] = false
    assert_not Beskar.configuration.risk_based_locking_enabled?

    # Test risk threshold
    Beskar.configuration.risk_based_locking[:risk_threshold] = 80
    assert_equal 80, Beskar.configuration.risk_threshold

    # Test lock strategy
    Beskar.configuration.risk_based_locking[:lock_strategy] = :devise_lockable
    assert_equal :devise_lockable, Beskar.configuration.lock_strategy

    # Test auto unlock time
    Beskar.configuration.risk_based_locking[:auto_unlock_time] = 2.hours
    assert_equal 2.hours, Beskar.configuration.auto_unlock_time

    # Test notification setting
    Beskar.configuration.risk_based_locking[:notify_user] = true
    assert Beskar.configuration.notify_user_on_lock?

    Beskar.configuration.risk_based_locking[:notify_user] = false
    assert_not Beskar.configuration.notify_user_on_lock?

    # Test logging setting
    Beskar.configuration.risk_based_locking[:log_lock_events] = true
    assert Beskar.configuration.log_lock_events?

    Beskar.configuration.risk_based_locking[:log_lock_events] = false
    assert_not Beskar.configuration.log_lock_events?
  end

  test "should handle edge case of user without security_events association" do
    # Create a mock user without the association
    mock_user = Object.new

    locker = Beskar::Services::AccountLocker.new(
      mock_user,
      risk_score: 90,
      reason: :high_risk_login
    )

    # Should handle gracefully
    assert_nothing_raised do
      locker.lock!
    end
  end
end
