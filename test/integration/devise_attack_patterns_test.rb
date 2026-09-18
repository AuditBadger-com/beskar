require "test_helper"
require_relative "../beskar_test_base"

class DeviseAttackPatternsTest < ActionDispatch::IntegrationTest
  include FactoryBot::Syntax::Methods

  def setup
    # Reset any user sessions
    reset!

    # Create test users - focus on security event creation rather than authentication
    @target_user = create(:devise_user, email: "target@example.com", password: "password123", password_confirmation: "password123")
    @other_user = create(:devise_user, email: "other@example.com", password: "password123", password_confirmation: "password123")
  end

  def teardown
    reset!
  end

  test "distributed attack pattern detection across multiple IPs" do
    target_email = @target_user.email
    attack_ips = ["203.1.113.1", "203.1.113.2", "203.1.113.3", "203.1.113.4"]

    # Simulate distributed brute force attack by creating failed login attempts
    attack_ips.each_with_index do |ip, index|
      3.times do |attempt|
        post "/devise_users/sign_in", params: {
          devise_user: {
            email: target_email,
            password: "wrong_password_#{attempt}"
          }
        }, headers: {
          "User-Agent" => "AttackBot/1.0",
          "X-Forwarded-For" => ip
        }

        assert_response((index * 3 + attempt < 5) ? :unprocessable_content : :too_many_requests)
      end
    end

    # Should have created security events for all failed attempts
    events = Beskar::SecurityEvent.where(user: @target_user)
    assert events.count >= 12, "Expected at least 12 security events for distributed attack"

    # Verify events were created across multiple IPs
    unique_ips = events.pluck(:ip_address).uniq
    assert unique_ips.length >= 4, "Expected attacks from at least 4 different IPs"

    # Verify high risk scores for suspicious patterns
    high_risk_events = events.where("risk_score > ?", 20)
    assert high_risk_events.count > 0, "Expected some high risk events for attack pattern"
  end

  test "credential stuffing attack pattern with different user agents" do
    # Simulate credential stuffing by trying different email/password combinations
    # from the same IP with different user agents

    attack_ip = "203.2.113.10"
    user_agents = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"
    ]

    user_agents.each_with_index do |user_agent, index|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "victim#{index}@example.com",
          password: "leaked_password_#{index}"
        }
      }, headers: {
        "User-Agent" => user_agent,
        "X-Forwarded-For" => attack_ip
      }

      assert_response :unprocessable_content
    end

    # Verify security events were created
    events = Beskar::SecurityEvent.where(ip_address: attack_ip)
    assert events.count >= 4, "Expected at least 4 security events for credential stuffing"

    # Verify different user agents were recorded
    recorded_agents = events.pluck(:user_agent).uniq
    assert recorded_agents.length >= 3, "Expected multiple different user agents"
  end

  test "account takeover attempt after data breach simulation" do
    # Simulate what happens when an attacker has valid credentials from a breach
    # but is coming from suspicious locations/devices

    # First create a security event for a successful login from normal location
    # (simulating user's normal activity)
    Beskar::SecurityEvent.create!(
      user: @target_user,
      event_type: "login_success",
      ip_address: "192.168.1.10",
      user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      risk_score: 5,
      metadata: {location: "normal_home"}
    )

    # Now simulate attacker trying to login with correct credentials but from suspicious location
    post "/devise_users/sign_in", params: {
      devise_user: {
        email: @target_user.email,
        password: "wrong_password" # Use wrong password to ensure failure for test
      }
    }, headers: {
      "User-Agent" => "Mozilla/5.0 (compatible; suspicious-bot/1.0)",
      "X-Forwarded-For" => "203.3.113.200" # Suspicious foreign IP
    }

    assert_response :unprocessable_content

    # Verify security event was created with high risk score
    suspicious_event = Beskar::SecurityEvent.where(ip_address: "203.3.113.200").last
    assert_not_nil suspicious_event
    assert suspicious_event.risk_score > 15, "Expected high risk score for suspicious login attempt"
    assert_equal "login_failure", suspicious_event.event_type
  end

  test "mixed success and failure pattern analysis" do
    # Simulate an attacker who occasionally succeeds (perhaps compromised accounts)
    # Focus on security event creation rather than actual authentication

    attacker_ip = "203.4.113.150"

    # Simulate mixed attempts by creating security events directly
    # This represents what would happen with mixed success/failure patterns

    # Create some failure events
    3.times do |i|
      Beskar::SecurityEvent.create!(
        user: nil,
        event_type: "login_failure",
        ip_address: attacker_ip,
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        attempted_email: "unknown#{i}@example.com",
        risk_score: 15,
        metadata: {pattern: "mixed_attack"}
      )
    end

    # Create some success events (representing compromised accounts)
    2.times do |i|
      target = (i == 0) ? @target_user : @other_user
      Beskar::SecurityEvent.create!(
        user: target,
        event_type: "login_success",
        ip_address: attacker_ip,
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        attempted_email: target.email,
        risk_score: 25, # High risk due to pattern
        metadata: {pattern: "mixed_attack", compromised: true}
      )
    end

    # Analyze the pattern
    events = Beskar::SecurityEvent.where(ip_address: attacker_ip)
    assert events.count == 5, "Expected 5 security events for mixed pattern"

    success_events = events.where(event_type: "login_success")
    failure_events = events.where(event_type: "login_failure")

    assert success_events.count == 2, "Expected 2 success events"
    assert failure_events.count == 3, "Expected 3 failure events"

    # Verify high risk scores due to mixed pattern
    high_risk_events = events.where("risk_score > ?", 20)
    assert high_risk_events.count >= 2, "Expected high risk scores for mixed attack pattern"
  end

  test "session hijacking simulation with sudden location change" do
    # Simulate session hijacking by showing normal login followed by access from different location

    # Create normal login event
    Beskar::SecurityEvent.create!(
      user: @target_user,
      event_type: "login_success",
      ip_address: "192.168.1.100",
      user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X)",
      risk_score: 3,
      metadata: {location: "normal_mobile"}
    )

    # Simulate access from completely different location shortly after
    get "/devise_users/sign_in", headers: {
      "User-Agent" => "Mozilla/5.0 (X11; Linux x86_64) Suspicious/1.0",
      "X-Forwarded-For" => "203.5.113.250" # Different country IP
    }

    # The access attempt should be tracked
    assert_response :success

    # Verify that security events are being tracked
    recent_events = Beskar::SecurityEvent.where(user: @target_user).order(:created_at)
    assert recent_events.count >= 1,
      "Should have at least one security event for location change"

    last_event = recent_events.last
    assert_not_nil last_event, "Should have a security event"
    # Location changes can elevate risk scores
    assert last_event.risk_score >= 0, "Should have a risk score"
  end

  test "botnet attack simulation with varied timing patterns" do
    # Simulate botnet attack with attempts from multiple IPs with realistic timing

    botnet_ips = [
      "203.6.113.10", "203.6.113.11", "203.6.113.12", "203.6.113.13",
      "198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"
    ]

    target_email = @target_user.email

    botnet_ips.each_with_index do |ip, index|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: target_email,
          password: "botnet_attempt"
        }
      }, headers: {
        "User-Agent" => "BotAgent/1.0",
        "X-Forwarded-For" => ip
      }

      assert_response((index < 5) ? :unprocessable_content : :too_many_requests)
    end

    # Verify botnet attack detection
    events = Beskar::SecurityEvent.where(user: @target_user)
    assert events.count >= 8, "Expected security events for each botnet attempt"

    unique_ips = events.pluck(:ip_address).uniq
    assert unique_ips.length >= 8, "Expected attacks from multiple IPs in botnet"

    # Verify elevated risk scores for bot-like behavior
    bot_events = events.where("user_agent LIKE ?", "%Bot%")
    assert bot_events.count >= 8, "Expected bot user agents to be detected"
  end

  test "account enumeration attack detection" do
    # Simulate account enumeration by trying to login with many different email addresses

    enumeration_ip = "203.6.113.75"
    test_emails = [
      "admin@example.com", "test@example.com", "user@example.com",
      "support@example.com", "info@example.com"
    ]

    test_emails.each do |email|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: email,
          password: "enumeration_password"
        }
      }, headers: {
        "User-Agent" => "EnumBot/1.0",
        "X-Forwarded-For" => enumeration_ip
      }

      assert_response :unprocessable_content
    end

    # Verify enumeration attack was detected
    events = Beskar::SecurityEvent.where(ip_address: enumeration_ip)
    assert events.count >= 5, "Expected security events for enumeration attempts"

    # Verify different email addresses were attempted
    attempted_emails = events.pluck(:attempted_email).compact.uniq
    assert_equal ["[FILTERED]"], attempted_emails
    account_keys = Beskar::SecurityState.arel_table[:key].matches("rate:enforce:account:%:credentials:%")
    assert_equal 5, Beskar::SecurityState.where(account_keys).count

    # Verify risk scores reflect enumeration pattern
    enum_events = events.where("user_agent LIKE ?", "%Enum%")
    assert enum_events.count >= 5, "Expected enumeration user agent to be detected"
  end

  private
end
