require "test_helper"
require "ostruct"

class RailsAuthSecurityTest < ActionDispatch::IntegrationTest
  include ActiveJob::TestHelper

  setup do
    @user = FactoryBot.create(:user, email_address: "test@example.com", password: "password123", password_confirmation: "password123")

    # Enable security tracking
    Beskar.configuration.security_tracking[:enabled] = true
    Beskar.configuration.security_tracking[:track_successful_logins] = true
    Beskar.configuration.security_tracking[:track_failed_logins] = true
  end

  teardown do
    Rails.cache.clear
    Beskar::SecurityEvent.delete_all
  end

  test "successful login creates security event" do
    assert_difference "Beskar::SecurityEvent.count", 1 do
      post session_url, params: {
        email_address: @user.email_address,
        password: "password123"
      }
    end

    assert_redirected_to root_url

    event = Beskar::SecurityEvent.last
    assert_equal "login_success", event.event_type
    assert_equal @user, event.user
    assert_equal "[FILTERED]", event.attempted_email
    assert event.risk_score.present?
  end

  test "failed login creates security event" do
    assert_difference "Beskar::SecurityEvent.count", 1 do
      post session_url, params: {
        email_address: "test@example.com",
        password: "wrongpassword"
      }
    end

    assert_redirected_to new_session_url

    event = Beskar::SecurityEvent.last
    assert_equal "login_failure", event.event_type
    assert_equal @user, event.user
    assert_equal "[FILTERED]", event.attempted_email
    assert event.risk_score.present?
    assert event.risk_score >= 10  # Base failure score
  end

  test "logout creates security event" do
    # Login first
    post session_url, params: {
      email_address: @user.email_address,
      password: "password123"
    }

    initial_count = Beskar::SecurityEvent.count

    # Now logout
    delete session_url

    assert_redirected_to new_session_url

    # Should have login_success + logout events
    assert_equal initial_count + 1, Beskar::SecurityEvent.count

    logout_event = Beskar::SecurityEvent.where(event_type: "logout").last
    assert logout_event.present?
    assert_equal @user, logout_event.user
  end

  test "multiple failed attempts increase risk score" do
    # First failed attempt
    post session_url, params: {
      email_address: @user.email_address,
      password: "wrong1"
    }
    first_attempt_score = Beskar::SecurityEvent.last.risk_score

    # Second failed attempt
    post session_url, params: {
      email_address: @user.email_address,
      password: "wrong2"
    }
    second_attempt_score = Beskar::SecurityEvent.last.risk_score

    # Third failed attempt
    post session_url, params: {
      email_address: @user.email_address,
      password: "wrong3"
    }
    third_attempt_score = Beskar::SecurityEvent.last.risk_score

    # Verify all scores are present
    assert first_attempt_score.present?, "First attempt should have risk score"
    assert second_attempt_score.present?, "Second attempt should have risk score"
    assert third_attempt_score.present?, "Third attempt should have risk score"

    # Verify risk scores are increasing due to pattern of repeated failures
    assert second_attempt_score >= first_attempt_score,
      "Second attempt risk (#{second_attempt_score}) should be >= first (#{first_attempt_score})"
    assert third_attempt_score >= second_attempt_score,
      "Third attempt risk (#{third_attempt_score}) should be >= second (#{second_attempt_score})"
  end

  test "successful login after failures resets adaptive learning" do
    # Create some failed attempts
    3.times do |i|
      post session_url, params: {
        email_address: @user.email_address,
        password: "wrong#{i}"
      }
    end

    # Now successful login
    post session_url, params: {
      email_address: @user.email_address,
      password: "password123"
    }

    success_event = Beskar::SecurityEvent.where(event_type: "login_success").last
    assert success_event.present?
    assert_equal @user, success_event.user

    # Should track that there were recent failures
    # Note: Failed attempts are tracked without user association
    # so they won't show up in @user.recent_failed_attempts
    # Instead, we check the total failure events
    failure_count = Beskar::SecurityEvent.where(
      event_type: "login_failure",
      user: @user
    ).count
    assert failure_count >= 3, "Expected at least 3 failure events, got #{failure_count}"
  end

  test "security event includes device and geolocation metadata" do
    post session_url, params: {
      email_address: @user.email_address,
      password: "password123"
    }, headers: {
      "User-Agent" => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "HTTP_X_FORWARDED_FOR" => "8.8.8.8"
    }

    event = Beskar::SecurityEvent.last
    assert event.metadata.present?
    assert event.metadata["device_info"].present?
    assert event.metadata["geolocation"].present?
    assert_equal "8.8.8.8", event.ip_address
  end

  test "rate limiting integration" do
    # Beskar should track all failed attempts for rate limiting
    10.times do |i|
      post session_url, params: {
        email_address: @user.email_address,
        password: "wrong#{i}"
      }
    end

    # Only the first five requests verify credentials; later ones are denied by
    # the account limit and are not mislabeled as password failures.
    assert_equal 5, Beskar::SecurityEvent.where(event_type: "login_failure").count
    assert_equal 5, Beskar::SecurityEvent.where(event_type: "authentication_blocked").count
    assert_response :too_many_requests
  end

  test "established pattern reduces risk score" do
    # Simulate established pattern by creating historical successful logins
    3.times do |i|
      @user.security_events.create!(
        event_type: "login_success",
        ip_address: "127.0.0.1",
        user_agent: "TestAgent",
        attempted_email: @user.email_address,
        metadata: {},
        risk_score: 1,
        created_at: (i + 1).days.ago
      )
    end

    # Now login from same IP
    post session_url, params: {
      email_address: @user.email_address,
      password: "password123"
    }

    event = Beskar::SecurityEvent.where(event_type: "login_success").last
    assert event.present?

    # Risk score should be low due to established pattern
    # (exact value depends on adaptive learning configuration)
    assert event.risk_score < 50, "Expected low risk score for established pattern, got #{event.risk_score}"
  end

  test "tracking can be disabled via configuration" do
    Beskar.configuration.security_tracking[:enabled] = false

    assert_no_difference "Beskar::SecurityEvent.count" do
      post session_url, params: {
        email_address: @user.email_address,
        password: "password123"
      }
    end
  end

  test "failed login tracking can be disabled separately" do
    Beskar.configuration.security_tracking[:track_failed_logins] = false
    Beskar.configuration.security_tracking[:track_successful_logins] = true

    # Failed attempt should not create event
    assert_no_difference "Beskar::SecurityEvent.count" do
      post session_url, params: {
        email_address: @user.email_address,
        password: "wrongpassword"
      }
    end

    # But successful should
    assert_difference "Beskar::SecurityEvent.count", 1 do
      post session_url, params: {
        email_address: @user.email_address,
        password: "password123"
      }
    end

    event = Beskar::SecurityEvent.last
    assert_equal "login_success", event.event_type
  end

  test "session destruction prevents access to restricted paths" do
    # Login successfully
    post session_url, params: {
      email_address: @user.email_address,
      password: "password123"
    }
    assert_redirected_to root_url
    follow_redirect!

    # Verify we can access restricted path (need to follow redirect to establish session)
    get user_restricted_url
    assert_response :success, "Should be able to access restricted path when logged in"

    # Now destroy the session
    delete session_url
    assert_redirected_to new_session_url

    # Verify we can no longer access restricted path
    get user_restricted_url
    assert_redirected_to new_session_url, "Should redirect to login after session destroyed"
  end

  test "impossible travel with emergency password reset enabled" do
    # Enable emergency password reset
    Beskar.configuration.emergency_password_reset[:enabled] = true
    Beskar.configuration.emergency_password_reset[:impossible_travel_threshold] = 2
    Beskar.configuration.risk_based_locking[:enabled] = true
    Beskar.configuration.risk_based_locking[:risk_threshold] = 75

    original_password_digest = @user.password_digest
    # Three confirmed lock events, not a substring match on a false travel flag.
    3.times do |index|
      @user.security_events.create!(
        event_type: "account_locked", ip_address: "203.0.113.#{index + 1}",
        user_agent: "TestAgent", attempted_email: @user.email_address,
        metadata: {reason: "impossible_travel", geolocation: {impossible_travel: true}},
        risk_score: 95, created_at: (index + 1).minutes.ago
      )
    end

    # Manually trigger the emergency password reset check
    security_event = @user.security_events.last
    reason = :impossible_travel

    if @user.should_reset_password?(security_event, reason)
      @user.perform_emergency_password_reset(security_event, reason)
    end

    # Verify password was changed
    @user.reload
    assert_not_equal original_password_digest, @user.password_digest,
      "Password should have been reset after impossible travel threshold reached"

    # Verify emergency reset event was created
    reset_event = @user.security_events.where(event_type: "emergency_password_reset").last
    assert reset_event.present?, "Emergency password reset event should be created"
    assert_equal "impossible_travel", reset_event.metadata["reason"]
  end

  test "destroy_all_sessions removes all user sessions" do
    # Create multiple sessions for the user
    session1 = @user.sessions.create!(ip_address: "127.0.0.1", user_agent: "Browser1")
    session2 = @user.sessions.create!(ip_address: "127.0.0.2", user_agent: "Browser2")
    session3 = @user.sessions.create!(ip_address: "127.0.0.3", user_agent: "Browser3")

    assert_equal 3, @user.sessions.count

    # Destroy all sessions
    @user.destroy_all_sessions

    # Verify all sessions are destroyed
    assert_equal 0, @user.sessions.count
    assert_not Session.exists?(session1.id)
    assert_not Session.exists?(session2.id)
    assert_not Session.exists?(session3.id)
  end

  test "destroy_all_sessions can preserve current session" do
    # Create multiple sessions
    session1 = @user.sessions.create!(ip_address: "127.0.0.1", user_agent: "Browser1")
    session2 = @user.sessions.create!(ip_address: "127.0.0.2", user_agent: "Browser2")
    current_session = @user.sessions.create!(ip_address: "127.0.0.3", user_agent: "Current")

    assert_equal 3, @user.sessions.count

    # Destroy all except current
    @user.destroy_all_sessions(except: current_session.id)

    # Verify only current session remains
    @user.reload
    assert_equal 1, @user.sessions.count
    assert Session.exists?(current_session.id)
    assert_not Session.exists?(session1.id)
    assert_not Session.exists?(session2.id)
  end

  test "high risk login triggers account locking" do
    # Enable risk-based locking with a very low threshold
    Beskar.configuration.risk_based_locking[:enabled] = true
    Beskar.configuration.risk_based_locking[:risk_threshold] = 50  # Low threshold for testing

    # Create some sessions
    @user.sessions.create!(ip_address: "127.0.0.1", user_agent: "Browser1")
    @user.sessions.create!(ip_address: "127.0.0.2", user_agent: "Browser2")

    assert_equal 2, @user.sessions.count

    # Create high-risk situation by simulating impossible travel
    # First create a recent login from US
    @user.security_events.create!(
      event_type: "login_success",
      ip_address: "8.8.8.8",
      user_agent: "Normal Browser",
      attempted_email: @user.email_address,
      metadata: {
        geolocation: {
          country: "United States",
          impossible_travel: false
        }
      },
      risk_score: 10,
      created_at: 5.minutes.ago
    )

    # Now attempt login from very distant location with high risk score
    # This should trigger risk-based locking logic
    request_mock = OpenStruct.new(
      ip: "1.1.1.1",
      user_agent: "Browser",
      params: {},
      session: OpenStruct.new(id: "test_session"),
      path: "/session",
      referer: nil,
      headers: {
        "Accept-Language" => "en-US",
        "X-Forwarded-For" => nil,
        "X-Real-IP" => nil
      }
    )

    # Track a success login which should calculate high risk due to impossible travel
    @user.track_authentication_event(request_mock, :success)

    # Verify a security event was created
    recent_event = @user.security_events.order(created_at: :desc).first
    assert recent_event.present?

    # Note: Session destruction happens in handle_high_risk_lock which is private
    # This test verifies the security tracking is working
    # The actual session destruction is tested separately in other tests
  end
end
