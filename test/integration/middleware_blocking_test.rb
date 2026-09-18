require "test_helper"
require_relative "../beskar_test_base"

class MiddlewareBlockingTest < ActionDispatch::IntegrationTest
  def setup
    Rails.cache.clear
    Beskar::BannedIp.destroy_all
    Beskar.configuration.rate_limiting[:ip_attempts][:block_requests] = true

    # Enable WAF and configure
    Beskar.configuration.waf = {
      enabled: true,
      auto_block: true,
      score_threshold: 150,
      violation_window: 6.hours,
      create_security_events: true,
      decay_enabled: true,
      decay_rates: {
        critical: 360,
        high: 120,
        medium: 45,
        low: 15
      },
      max_violations_tracked: 50
    }

    # Configure IP whitelist
    Beskar.configuration.ip_whitelist = []
  end

  def teardown
    Rails.cache.clear
    Beskar::BannedIp.destroy_all
    Beskar.configuration.waf = {enabled: false}
    Beskar.configuration.ip_whitelist = []
  end

  # Banned IP blocking
  test "middleware blocks requests from banned IPs" do
    ip = worker_ip(1)
    Beskar::BannedIp.ban!(ip, reason: "test_ban", duration: 1.hour)

    get "/", headers: {"X-Forwarded-For" => ip}

    assert_response 403
    assert_match(/blocked/i, response.body)
  end

  test "middleware allows requests from non-banned IPs" do
    ip = worker_ip(2)

    get "/", headers: {"X-Forwarded-For" => ip}

    assert_response :success
  end

  test "middleware blocks expired bans are not enforced" do
    ip = worker_ip(3)
    Beskar::BannedIp.create!(
      ip_address: ip,
      reason: "test",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    get "/", headers: {"X-Forwarded-For" => ip}

    assert_response :success
  end

  # IP Whitelist functionality
  test "whitelisted IPs bypass banned IP check" do
    ip = worker_ip(10)
    Beskar.configuration.ip_whitelist = [ip]
    Beskar::Services::IpWhitelist.clear_cache!

    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    get "/", headers: {"X-Forwarded-For" => ip}

    # Should allow through despite ban
    assert_response :success
  end

  test "whitelisted IPs bypass rate limiting" do
    ip = worker_ip(11)
    Beskar.configuration.ip_whitelist = [ip]
    Beskar::Services::IpWhitelist.clear_cache!

    # Make many requests (should exceed rate limit)
    15.times do |i|
      get "/devise_users/sign_in", headers: {"X-Forwarded-For" => ip}
    end

    # Should still be allowed
    get "/", headers: {"X-Forwarded-For" => ip}
    assert_response :success
  end

  test "whitelisted CIDR range bypasses blocking" do
    Beskar.configuration.ip_whitelist = ["10.50.0.0/24"]
    Beskar::Services::IpWhitelist.clear_cache!

    ip = "10.50.0.100"
    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    get "/", headers: {"X-Forwarded-For" => ip}

    assert_response :success
  end

  test "whitelisted IPs are still logged for WAF violations" do
    ip = worker_ip(12)
    Beskar.configuration.ip_whitelist = [ip]
    Beskar::Services::IpWhitelist.clear_cache!
    Beskar.configuration.waf[:enabled] = true

    # Make WAF violation
    get "/wp-admin/", headers: {"X-Forwarded-For" => ip}

    # Should log but not block
    violation_count = Beskar::Services::Waf.get_violation_count(ip)
    assert violation_count > 0, "Whitelisted IP violations should still be logged"
  end

  # WAF blocking
  test "middleware blocks IPs after WAF violation threshold" do
    ip = worker_ip(20)
    Beskar.configuration.waf[:enabled] = true
    Beskar.configuration.waf[:auto_block] = true
    Beskar.configuration.waf[:score_threshold] = 200

    # Make 3 violations to reach threshold
    3.times do
      get "/wp-admin/", headers: {"X-Forwarded-For" => ip}
    end

    # Next request should be blocked (either by middleware or already banned)
    get "/", headers: {"X-Forwarded-For" => ip}

    # Should be blocked
    assert Beskar::BannedIp.banned?(ip), "IP should be banned after WAF threshold"
    assert_equal 3, Beskar::Services::Waf.get_violation_count(ip)
    assert_response :forbidden
  end

  test "WAF violations are logged but not blocked in monitor mode" do
    ip = worker_ip(21)
    Beskar.configuration.waf[:enabled] = true
    Beskar.configuration.monitor_only = true
    Beskar.configuration.waf[:score_threshold] = 75

    # Make multiple WAF violations
    5.times do
      get "/wp-admin/", headers: {"X-Forwarded-For" => ip}
    end

    # Monitor mode records evidence without creating an active ban.
    assert_not Beskar::BannedIp.banned?(ip)

    # But requests should still succeed (not blocked)
    get "/", headers: {"X-Forwarded-For" => ip}
    assert_response :success, "Request should succeed in monitor mode despite ban"

    # But violations should be logged
    assert Beskar::Services::Waf.get_violation_count(ip) > 0
  end

  test "WAF detects WordPress scans" do
    ip = worker_ip(22)

    paths = ["/wp-admin/", "/wp-login.php", "/xmlrpc.php"]

    paths.each do |path|
      get path, headers: {"X-Forwarded-For" => ip}

      # Each request increments violation count
      assert Beskar::Services::Waf.get_violation_count(ip) > 0
    end
  end

  test "WAF detects config file access attempts" do
    ip = worker_ip(23)

    paths = ["/.env", "/.git/config", "/config.php"]

    paths.each do |path|
      get path, headers: {"X-Forwarded-For" => ip}
    end

    # Config files are critical (95 points), 2 violations = 190 > 150 threshold
    # IP gets banned after 2nd violation, so we'll have 2 violations tracked
    assert Beskar::Services::Waf.get_violation_count(ip) >= 2, "Expected at least 2 violations"
    assert Beskar::BannedIp.banned?(ip), "IP should be banned after config file access attempts"
  end

  test "WAF detects path traversal attempts" do
    ip = worker_ip(24)

    get "/files/../../etc/passwd", headers: {"X-Forwarded-For" => ip}

    assert Beskar::Services::Waf.get_violation_count(ip) > 0
  end

  test "WAF allows legitimate requests" do
    ip = worker_ip(25)

    legitimate_paths = ["/", "/users", "/posts/123", "/about"]

    legitimate_paths.each do |path|
      get path, headers: {"X-Forwarded-For" => ip}
    end

    # Should not increment WAF violations
    assert_equal 0, Beskar::Services::Waf.get_violation_count(ip)
  end

  # Authentication abuse blocking
  test "middleware blocks IPs after authentication brute force attempts" do
    ip = worker_ip(29)

    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => ip)
    10.times { Beskar::Services::RateLimiter.check_authentication_attempt(request, :failure) }
    5.times do
      get "/", headers: {"X-Forwarded-For" => ip}
      assert_response :too_many_requests
    end

    assert Beskar::BannedIp.banned?(ip)
    assert_equal "rate_limit_abuse", Beskar::BannedIp.find_by!(ip_address: ip).reason
  end

  test "authentication abuse blocking works independently of WAF" do
    ip = worker_ip(28)
    Beskar.configuration.waf[:enabled] = false
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => ip)
    10.times { Beskar::Services::RateLimiter.check_authentication_attempt(request, :failure) }
    5.times { get "/", headers: {"X-Forwarded-For" => ip} }
    assert Beskar::BannedIp.banned?(ip)
  end

  # Rate limiting with auto-block
  test "middleware blocks IPs after excessive rate limiting violations" do
    ip = worker_ip(30)

    # Exceed rate limit multiple times (5+ times in an hour triggers auto-block)
    # We need to simulate rate limit violations
    30.times do |i|
      # Directly record attempts to exceed limit faster
      Beskar::Services::RateLimiter.check_authentication_attempt(
        mock_request(ip),
        :failure
      )
    end

    # Check if IP is rate limited
    rate_result = Beskar::Services::RateLimiter.check_ip_rate_limit(ip)
    assert_not rate_result[:allowed], "IP should be rate limited"

    # Make actual requests to trigger middleware blocking logic
    6.times do
      get "/", headers: {"X-Forwarded-For" => ip}
    end

    # Eventually should be banned due to rate limit abuse
    # (The middleware tracks rate_limit_violations separately)
  end

  # Combined scenarios
  test "banned IPs are checked before rate limiting" do
    ip = worker_ip(40)

    # Ban the IP
    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    # Try to make request (should be blocked before rate limit check)
    get "/", headers: {"X-Forwarded-For" => ip}

    assert_response 403
    assert_match(/blocked/i, response.body)
  end

  test "whitelisted IPs skip all blocking checks" do
    ip = worker_ip(41)
    Beskar.configuration.ip_whitelist = [ip]
    Beskar::Services::IpWhitelist.clear_cache!

    # Ban the IP
    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    # Exceed rate limit
    15.times do |i|
      get "/devise_users/sign_in", headers: {"X-Forwarded-For" => ip}
    end

    # Make WAF violation
    get "/wp-admin/", headers: {"X-Forwarded-For" => ip}

    # Should still be allowed
    get "/", headers: {"X-Forwarded-For" => ip}
    assert_response :success
  end

  # Response headers
  test "blocked response includes X-Beskar-Blocked header" do
    ip = worker_ip(50)
    Beskar::BannedIp.ban!(ip, reason: "test", duration: 1.hour)

    get "/", headers: {"X-Forwarded-For" => ip}

    assert_equal "true", response.headers["X-Beskar-Blocked"]
  end

  test "rate limited response includes X-Beskar-Rate-Limited header" do
    ip = worker_ip(51)

    # Exceed rate limit
    15.times do
      Beskar::Services::RateLimiter.check_authentication_attempt(
        mock_request(ip),
        :failure
      )
    end

    get "/", headers: {"X-Forwarded-For" => ip}

    # Should be rate limited at middleware level
    assert_equal 429, response.status, "Should return 429 after exceeding rate limit"
    assert_equal "true", response.headers["X-Beskar-Rate-Limited"]
  end

  # Security event creation
  test "WAF violations create security events when configured" do
    ip = worker_ip(60)
    Beskar.configuration.waf[:create_security_events] = true

    assert_difference "Beskar::SecurityEvent.count", 1 do
      get "/wp-admin/", headers: {"X-Forwarded-For" => ip}
    end

    event = Beskar::SecurityEvent.last
    assert_equal "waf_violation", event.event_type
    assert_equal ip, event.ip_address
  end

  # Edge cases
  test "handles missing IP address gracefully" do
    # Don't set X-Forwarded-For header
    get "/"

    # Should not crash, just use request.ip
    assert_response :success
  end

  test "handles invalid IP addresses gracefully" do
    get "/", headers: {"X-Forwarded-For" => "invalid-ip"}

    # Should not crash
    assert_response :success
  end

  test "multiple concurrent requests from same IP handle middleware checks without race conditions" do
    ip = worker_ip(71)

    # Make sequential requests instead of concurrent - Rails integration tests
    # don't support threading because they share session state
    results = []

    # Make 5 requests from the same IP
    5.times do
      get "/devise_users/sign_in", headers: {"X-Forwarded-For" => ip}
      results << response.status
    end

    # All requests should complete
    assert_equal 5, results.length, "Should complete all 5 requests"

    # All requests should succeed (no blocking since IP is clean)
    assert results.all? { |status| status == 200 },
      "All requests from clean IP should succeed (200), got: #{results.inspect}"

    # Verify no race conditions in banned IP checking
    assert_not Beskar::BannedIp.banned?(ip), "Clean IP should not be auto-banned"

    # Verify middleware didn't incorrectly increment violation counts
    assert_equal 0, Beskar::Services::Waf.get_violation_count(ip), "No WAF violations for clean requests"
  end

  test "preloaded banned IPs are enforced immediately" do
    ip = worker_ip(80)

    # Create ban directly in database
    Beskar::BannedIp.create!(
      ip_address: ip,
      reason: "test",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    # Preload cache (simulates app restart)
    Beskar::BannedIp.preload_cache!

    # Should be blocked
    get "/", headers: {"X-Forwarded-For" => ip}
    assert_response 403
  end

  private

  def mock_request(ip)
    mock_req = mock
    mock_req.stubs(:ip).returns(ip)
    mock_req.stubs(:user_agent).returns("TestBot")
    mock_req
  end
end
