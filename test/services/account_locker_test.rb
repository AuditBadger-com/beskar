require "test_helper"

module Beskar
  module Services
    class AccountLockerTest < ActiveSupport::TestCase
      setup do
        @user = DeviseUser.create!(
          email: "test@example.com",
          password: "password123",
          password_confirmation: "password123"
        )

        # Reset configuration to defaults
        Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
      end

      test "should not lock when risk-based locking is disabled" do
        Beskar.configuration.risk_based_locking[:enabled] = false

        locker = AccountLocker.new(@user, risk_score: 90, reason: :high_risk_login)

        assert_not locker.should_lock?
        assert_not locker.lock_if_necessary!
      end

      test "should not lock when risk score is below threshold" do
        Beskar.configuration.risk_based_locking[:enabled] = true
        Beskar.configuration.risk_based_locking[:risk_threshold] = 75

        locker = AccountLocker.new(@user, risk_score: 50, reason: :high_risk_login)

        assert_not locker.should_lock?
        assert_not locker.lock_if_necessary!
      end

      test "should lock when risk score exceeds threshold" do
        Beskar.configuration.risk_based_locking[:enabled] = true
        Beskar.configuration.risk_based_locking[:risk_threshold] = 75

        locker = AccountLocker.new(@user, risk_score: 85, reason: :high_risk_login)

        assert locker.should_lock?
      end

      test "should recognize when devise lockable is not available" do
        Beskar.configuration.risk_based_locking[:enabled] = true
        Beskar.configuration.risk_based_locking[:lock_strategy] = :devise_lockable

        locker = AccountLocker.new(@user, risk_score: 90, reason: :high_risk_login)

        # DeviseUser model now has :lockable module enabled, so lock should succeed
        assert locker.lock!
        assert @user.reload.access_locked?
      end

      test "unsupported custom strategy fails explicitly" do
        Beskar.configuration.risk_based_locking[:enabled] = true
        Beskar.configuration.risk_based_locking[:lock_strategy] = :custom
        Beskar.configuration.risk_based_locking[:risk_threshold] = 75

        locker = AccountLocker.new(@user, risk_score: 85, reason: :high_risk_login)

        assert_raises(Beskar::Configuration::Error) { locker.lock! }
        assert_raises(Beskar::Configuration::Error) { locker.unlock! }
        refute @user.reload.access_locked?
      end

      test "should not lock user twice" do
        Beskar.configuration.risk_based_locking[:enabled] = true
        Beskar.configuration.risk_based_locking[:risk_threshold] = 75

        # Mock the user as already locked
        @user.define_singleton_method(:access_locked?) { true }

        locker = AccountLocker.new(@user, risk_score: 90, reason: :high_risk_login)

        assert_not locker.should_lock?
      end

      test "should log lock event when configured" do
        Beskar.configuration.risk_based_locking[:enabled] = true
        Beskar.configuration.risk_based_locking[:log_lock_events] = true
        Beskar.configuration.risk_based_locking[:risk_threshold] = 75
        Beskar.configuration.risk_based_locking[:lock_strategy] = :none

        locker = AccountLocker.new(
          @user,
          risk_score: 85,
          reason: :high_risk_login,
          metadata: {ip_address: "192.168.1.1", user_agent: "Test Browser"}
        )

        # Explicitly disabled locking records an attempt, never a successful lock.
        initial_count = @user.security_events.count
        locker.lock!

        # CHANGED BEHAVIOR: Lock events are always logged when log_lock_events is true
        # This creates an audit trail even if actual locking fails
        assert_equal initial_count + 1, @user.security_events.count

        # The event type should be 'lock_attempted' since actual lock failed
        last_event = @user.security_events.last
        assert_equal "lock_attempted", last_event.event_type
      end

      test "should check locked status correctly" do
        locker = AccountLocker.new(@user, risk_score: 50)

        assert_not locker.locked?

        # Mock locked state
        @user.define_singleton_method(:access_locked?) { true }

        assert locker.locked?
      end

      test "should handle nil user gracefully" do
        locker = AccountLocker.new(nil, risk_score: 90, reason: :high_risk_login)

        assert_not locker.should_lock?
        assert_not locker.lock!
        assert_not locker.unlock!
        assert_not locker.locked?
      end

      test "should use correct risk threshold from configuration" do
        Beskar.configuration.risk_based_locking[:enabled] = true
        Beskar.configuration.risk_based_locking[:risk_threshold] = 80

        locker = AccountLocker.new(@user, risk_score: 79)
        assert_not locker.should_lock?

        locker = AccountLocker.new(@user, risk_score: 80)
        assert locker.should_lock?

        locker = AccountLocker.new(@user, risk_score: 81)
        assert locker.should_lock?
      end

      test "should include metadata in lock decision" do
        Beskar.configuration.risk_based_locking[:enabled] = true
        Beskar.configuration.risk_based_locking[:risk_threshold] = 75

        metadata = {
          ip_address: "203.0.113.1",
          user_agent: "Suspicious Bot",
          geolocation: {country: "Unknown"}
        }

        locker = AccountLocker.new(
          @user,
          risk_score: 85,
          reason: :suspicious_device,
          metadata: metadata
        )

        assert_equal metadata, locker.metadata
        assert_equal :suspicious_device, locker.reason
      end
    end
  end
end
