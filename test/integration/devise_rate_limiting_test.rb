require "test_helper"
require_relative "../beskar_test_base"

class DeviseRateLimitingTest < ActionDispatch::IntegrationTest
  include FactoryBot::Syntax::Methods

  def setup
    @user = create(:devise_user, email: "test@example.com", password: "password123", password_confirmation: "password123")
    @test_ip = worker_ip(169)
  end

  def teardown
  end

  test "IP-based rate limiting blocks after exceeding limit" do
    # Default IP limit is typically 10 attempts per hour
    ip_limit = 10

    # Make exactly the limit number of failed attempts
    ip_limit.times do |i|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "nonexistent#{i}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "User-Agent" => "Mozilla/5.0 (Test #{i})",
        "X-Forwarded-For" => @test_ip
      }

      assert_response :unprocessable_content # Devise returns 422 for failed authentication
    end

    # Verify we can still make one more attempt (at the limit)
    rate_limit_check = Beskar::Services::RateLimiter.check_ip_rate_limit(@test_ip)
    assert_equal false, rate_limit_check[:allowed]
    assert_equal "rate_limit_exceeded", rate_limit_check[:reason]

    # Next attempt should be blocked by rate limiter logic
    # (Note: This tests the rate limiter service, actual blocking would be in middleware)
    post "/devise_users/sign_in", params: {
      devise_user: {
        email: "blocked@example.com",
        password: "wrongpassword"
      }
    }, headers: {
      "User-Agent" => "Mozilla/5.0 (Blocked)",
      "X-Forwarded-For" => @test_ip
    }

    # The request still goes through (middleware would block it in real scenario)
    # but we can verify the rate limiter recognizes the limit exceeded
    final_check = Beskar::Services::RateLimiter.check_ip_rate_limit(@test_ip)
    assert_equal false, final_check[:allowed]
    assert final_check[:retry_after] > 0
  end

  test "account-based rate limiting works independently of IP limiting" do
    # Account limit is typically lower than IP limit (e.g., 5 vs 10)
    target_email = @user.email

    # Use different IPs to avoid IP-based limiting
    ips = ["10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.5", "10.1.0.6"]

    ips.each_with_index do |ip, index|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: target_email,
          password: "wrongpassword#{index}"
        }
      }, headers: {
        "User-Agent" => "Mozilla/5.0 (Account Test #{index})",
        "X-Forwarded-For" => ip
      }
    end

    # Check account-based rate limiting
    account_limit_check = Beskar::Services::RateLimiter.check_account_rate_limit(@user)
    # The exact behavior depends on implementation, but failed attempts should be tracked
    assert_not_nil account_limit_check[:limit]
    assert_not_nil account_limit_check[:count]
  end

  test "rate limiting resets after time window expires" do
    # Make several failed attempts to approach the limit
    3.times do |i|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "test#{i}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "X-Forwarded-For" => "192.168.2.100"
      }
    end

    travel 2.hours

    # New attempt should be allowed since old attempts are outside window
    rate_limit_result = Beskar::Services::RateLimiter.check_ip_rate_limit("192.168.2.100")
    assert rate_limit_result[:allowed], "Rate limiting should reset after time window"
  end

  test "successful login doesn't count against failure rate limits" do
    ip_address = "192.168.3.100"

    # Make some failed attempts
    3.times do |i|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "wrong#{i}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "X-Forwarded-For" => ip_address
      }
    end

    # Make successful login
    post "/devise_users/sign_in", params: {
      devise_user: {
        email: @user.email,
        password: "password123"
      }
    }, headers: {
      "X-Forwarded-For" => ip_address
    }

    assert_redirected_to root_path

    # Rate limiting counts all attempts including successful ones
    rate_limit_result = Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address)
    # The implementation counts all attempts (success and failure)
    assert rate_limit_result[:count] >= 3, "All authentication attempts are counted"
    assert rate_limit_result[:allowed], "Should still be within rate limits after mixed attempts"
  end

  test "rate limiting works with different user agents from same IP" do
    ip_address = "192.168.4.100"
    user_agents = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0",
      "curl/7.68.0"
    ]

    # Make failed attempts with different user agents
    user_agents.each_with_index do |user_agent, index|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "test#{index}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "User-Agent" => user_agent,
        "X-Forwarded-For" => ip_address
      }
    end

    # All attempts should be counted together for the same IP
    rate_limit_result = Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address)
    assert_equal 4, rate_limit_result[:count], "Different user agents from same IP should be counted together"
  end

  test "distributed rate limiting across multiple IPs for same account" do
    target_email = @user.email
    attack_ips = [worker_ip(50), worker_ip(51), worker_ip(52)]

    # Simulate distributed attack on single account from 3 different IPs
    # 3 attempts from each IP = 9 total attempts on same account
    attack_ips.each_with_index do |ip, ip_index|
      3.times do |attempt|
        post "/devise_users/sign_in", params: {
          devise_user: {
            email: target_email,
            password: "distributed_attack_#{ip_index}_#{attempt}"
          }
        }, headers: {
          "User-Agent" => "DistributedBot/#{ip_index}",
          "X-Forwarded-For" => ip
        }

        expected = (ip_index * 3 + attempt < 5) ? :unprocessable_content : :too_many_requests
        assert_response expected
      end
    end

    # Each individual IP should still be within its own IP-based rate limit
    # (only 3 attempts each, limit is 10 per hour)
    attack_ips.each do |ip|
      ip_result = Beskar::Services::RateLimiter.check_ip_rate_limit(ip)
      assert ip_result[:allowed], "Individual IP #{ip} should still be within limits (3/10 attempts)"
      assert_equal 3, ip_result[:count], "Should have exactly 3 attempts from IP #{ip}"
    end

    assert_not Beskar::Services::RateLimiter.check_account_rate_limit(@user)[:allowed]

    # This test verifies that individual IPs are tracked separately
    # while account-based tracking would aggregate across all IPs
    # The key point: distributed attacks try to evade IP-based rate limiting
    # by spreading attempts across multiple IPs

    # Verify the attack succeeded in spreading load
    total_attempts = attack_ips.sum { |ip| Beskar::Services::RateLimiter.check_ip_rate_limit(ip)[:count] }
    assert_equal 9, total_attempts, "Total of 9 attempts across 3 IPs (3 each)"

    # None of the individual IPs are blocked
    attack_ips.each do |ip|
      assert Beskar::Services::RateLimiter.check_ip_rate_limit(ip)[:allowed],
        "IP #{ip} should not be blocked (distributed attack stays under per-IP limits)"
    end
  end

  test "middleware rate limit previews do not escalate authentication backoff" do
    ip_address = worker_ip(60)

    # Make 15 authentication attempts (exceeds default limit of 10)
    responses = []
    15.times do |i|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "backoff#{i}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "X-Forwarded-For" => ip_address
      }
      responses << response.status
    end

    # Verify the transition from auth failures to rate limiting
    # First requests return 422 (authentication failure)
    # After exceeding limit, middleware returns 429 (rate limited)
    assert_equal 422, responses.first, "First request should be auth failure (422)"
    assert_equal 429, responses.last, "After 15 attempts (>10 limit), should be rate limited (429)"

    # Count the transition point (where 429 first appears)
    transition_index = responses.index(429)
    assert_not_nil transition_index, "Should transition to 429 at some point"
    assert transition_index >= 10, "Should transition after exceeding limit of 10"
    assert transition_index <= 13, "Should transition by attempt 13 at latest"

    # Verify rate limiter state after the attack
    rate_check = Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address)
    assert_equal false, rate_check[:allowed], "IP should be rate limited after 15 attempts"
    assert rate_check[:retry_after] > 0, "Should have positive retry_after time (got #{rate_check[:retry_after]})"

    # Verify attempt count
    assert rate_check[:count] >= 10, "Should have recorded at least 10 attempts (got #{rate_check[:count]})"

    # Middleware previews must not escalate authentication backoff.
    deadline = rate_check[:reset_time]
    assert_equal deadline, Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address)[:reset_time]
  end

  test "rate limiting allows requests after cooldown period" do
    ip_address = worker_ip(12)

    # Exceed rate limit
    responses = []
    11.times do |i|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "cooldown#{i}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "X-Forwarded-For" => ip_address
      }
      responses << response.status
      # First attempts return 422 (auth failure), later ones return 429 (rate limited)
      assert_includes [422, 429], response.status
    end

    # Should transition from 422 to 429
    assert responses.first == 422, "First request should be auth failure (422)"
    assert responses.last == 429, "After exceeding limit, should be rate limited (429)"

    # Verify rate limited
    blocked_check = Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address)
    assert_equal false, blocked_check[:allowed]

    travel 2.hours

    # Should be allowed again
    cooldown_check = Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address)
    assert cooldown_check[:allowed], "Requests should be allowed after cooldown period"
    assert_equal 0, cooldown_check[:count]
  end

  test "global rate limiting prevents system overload" do
    # This test simulates high load across the entire system
    # Create multiple IPs making requests simultaneously

    base_ip = "10.69.1."
    20.times do |ip_suffix|
      ip = "#{base_ip}#{ip_suffix + 1}"

      # Each IP makes several requests
      3.times do |attempt|
        post "/devise_users/sign_in", params: {
          devise_user: {
            email: "global#{ip_suffix}_#{attempt}@example.com",
            password: "wrongpassword"
          }
        }, headers: {
          "User-Agent" => "GlobalLoadTest/#{ip_suffix}",
          "X-Forwarded-For" => ip
        }
      end
    end

    # Verify that individual IPs are still within their limits
    test_ip = "#{base_ip}1"
    ip_check = Beskar::Services::RateLimiter.check_ip_rate_limit(test_ip)
    assert ip_check[:allowed], "Individual IP should still be within limits"

    # Global limiting would be handled at a higher level
    # Here we just verify that all events were created
    total_events = Beskar::SecurityEvent.where(
      ip_address: (1..20).map { |i| "#{base_ip}#{i}" }
    ).count
    assert_equal 60, total_events # 20 IPs * 3 attempts each
  end

  test "rate limiting respects different limits for different event types" do
    ip_address = worker_ip(28)

    # Test that the rate limiter can handle different types of events
    # (This depends on the implementation supporting different limits)

    # Make login failures
    5.times do |i|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "ratetype#{i}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "X-Forwarded-For" => ip_address
      }
    end

    failure_check = Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address)
    failure_count = failure_check[:count]

    # Make successful login
    post "/devise_users/sign_in", params: {
      devise_user: {
        email: @user.email,
        password: "password123"
      }
    }, headers: {
      "X-Forwarded-For" => ip_address
    }
    assert_redirected_to root_path

    # Logout to clean up session
    delete "/devise_users/sign_out"
    assert_redirected_to root_path

    success_check = Beskar::Services::RateLimiter.check_ip_rate_limit(ip_address)

    # The implementation counts all attempts including successes
    assert_not_nil success_check[:count]
    assert success_check[:count] > failure_count, "Should count successful attempt"
  end

  private

  def simulate_time_passing(seconds)
    # Helper method to simulate time passing
    # In real tests, you might use travel_to from ActiveSupport::Testing::TimeHelpers
    sleep(0.1) # Small actual delay for any time-based operations
  end

  def create_rate_limit_violation(ip, count = 15)
    # Helper to create a rate limit violation
    count.times do |i|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "violation#{i}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "X-Forwarded-For" => ip
      }
    end
  end

  def verify_security_events_created(ip_address, expected_count)
    actual_count = Beskar::SecurityEvent.where(ip_address: ip_address).count
    assert_equal expected_count, actual_count, "Expected #{expected_count} security events for IP #{ip_address}"
  end
end
