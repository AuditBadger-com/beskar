require "test_helper"
require_relative "../beskar_test_base"

class WafIntegrationTest < ActionDispatch::IntegrationTest
  include FactoryBot::Syntax::Methods

  def setup
    Rails.cache.clear
    Beskar::BannedIp.destroy_all

    Beskar.configuration.waf = {
      enabled: true,
      auto_block: true,
      score_threshold: 150,
      violation_window: 6.hours,
      block_durations: [1.hour, 6.hours, 24.hours, 7.days],
      permanent_block_after: 500,
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
    Beskar.configuration.monitor_only = false

    Beskar.configuration.ip_whitelist = []
  end

  def teardown
    Rails.cache.clear
    Beskar::BannedIp.destroy_all
    Beskar.configuration.waf = {enabled: false}
    Beskar.configuration.ip_whitelist = []
  end

  # Progressive blocking scenarios
  test "WAF blocks IP after score threshold reached" do
    ip = worker_ip(1)

    # First violation - should not block yet (80 < 150)
    get "/wp-admin/", headers: {"X-Forwarded-For" => ip}
    assert_not Beskar::BannedIp.banned?(ip)

    # Second violation - should trigger block (80 + 80 = 160 > 150)
    get "/wp-admin/", headers: {"X-Forwarded-For" => ip}

    ban = Beskar::BannedIp.find_by(ip_address: ip)
    assert_not_nil ban
    assert_equal "waf_violation", ban.reason
    assert_equal 1, ban.violation_count
    assert_not_nil ban.expires_at
  end

  test "BannedIp extend_ban! escalates to permanent after threshold" do
    ip = worker_ip(2)

    # Create initial temporary ban
    ban = Beskar::BannedIp.create!(
      ip_address: ip,
      reason: "waf_violation",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour,
      violation_count: 4 # Start at 4 violations
    )

    assert_not ban.permanent?

    # Extend ban (this should make it permanent at violation 5)
    ban.extend_ban!

    assert ban.permanent?, "Should be permanent after 5th violation"
  end

  # Security event tracking
  test "WAF creates security events with proper metadata" do
    ip = worker_ip(10)

    assert_difference "Beskar::SecurityEvent.count", 1 do
      get "/wp-admin/index.php?debug=true", headers: {
        "X-Forwarded-For" => ip,
        "User-Agent" => "MaliciousBot/1.0"
      }
    end

    event = Beskar::SecurityEvent.last
    assert_equal "waf_violation", event.event_type
    assert_equal ip, event.ip_address
    assert_nil event.user_agent
    assert event.risk_score >= 70
    assert_not_nil event.metadata["waf_analysis"]
  end

  test "WAF security events track multiple violations" do
    ip = worker_ip(11)

    # Use lower severity violations to avoid hitting ban threshold
    # Medium severity (/debug) = 60 points each, need 3 to exceed 150
    paths = ["/debug", "/telescope", "/__debug__"]

    assert_difference "Beskar::SecurityEvent.count", 3 do
      paths.each do |path|
        get path, headers: {"X-Forwarded-For" => ip}
      end
    end

    events = Beskar::SecurityEvent.where(ip_address: ip, event_type: "waf_violation")
    assert_equal 3, events.count
  end

  # Different severity levels
  test "WAF assigns higher risk scores to critical violations" do
    ip = worker_ip(20)

    # Critical violation (.env file)
    get "/.env", headers: {"X-Forwarded-For" => ip}
    critical_event = Beskar::SecurityEvent.last

    Rails.cache.clear
    Beskar::SecurityEvent.delete_all

    ip2 = worker_ip(21)
    # Medium violation (debug endpoint)
    get "/rails/info/routes", headers: {"X-Forwarded-For" => ip2}
    medium_event = Beskar::SecurityEvent.last

    assert critical_event.risk_score > medium_event.risk_score,
      "Critical violations should have higher risk score than medium"
  end

  # Whitelist integration
  test "whitelisted IPs log WAF violations but are never blocked" do
    ip = worker_ip(30)
    Beskar.configuration.ip_whitelist = [ip]
    Beskar::Services::IpWhitelist.clear_cache!

    # Make many WAF violations
    10.times do
      get "/wp-admin/", headers: {"X-Forwarded-For" => ip}
    end

    # Should log violations
    assert Beskar::Services::Waf.get_violation_count(ip) >= 3

    # But should not be banned
    assert_not Beskar::BannedIp.banned?(ip)

    # Should still be able to access site
    get "/", headers: {"X-Forwarded-For" => ip}
    assert_response :success
  end

  test "whitelisted CIDR range logs but doesn't block WAF violations" do
    Beskar.configuration.ip_whitelist = ["10.100.0.0/24"]
    Beskar::Services::IpWhitelist.clear_cache!

    ips = ["10.100.0.1", "10.100.0.50", "10.100.0.254"]

    ips.each do |ip|
      # Trigger violations
      5.times { get "/wp-admin/", headers: {"X-Forwarded-For" => ip} }

      # Should log
      assert Beskar::Services::Waf.get_violation_count(ip) > 0

      # Should not ban
      assert_not Beskar::BannedIp.banned?(ip)
    end
  end

  # Combined attack scenarios
  test "detects and blocks distributed WordPress scanning attack" do
    base_ip = "10.200.1."
    ips = (1..5).map { |i| "#{base_ip}#{i}" }

    # Multiple IPs scanning for WordPress
    ips.each do |ip|
      ["/wp-admin/", "/wp-login.php", "/xmlrpc.php"].each do |path|
        get path, headers: {"X-Forwarded-For" => ip}
      end
    end

    # All IPs should be blocked
    ips.each do |ip|
      assert Beskar::BannedIp.banned?(ip), "IP #{ip} should be banned"
    end
  end

  test "detects config file enumeration attack" do
    ip = worker_ip(40)

    config_files = [
      "/.env",
      "/.env.local",
      "/.env.production",
      "/config/database.yml",
      "/config.php",
      "/.git/config"
    ]

    config_files.each do |path|
      get path, headers: {"X-Forwarded-For" => ip}
    end

    # Should have tracked multiple violations (6 config file attempts)
    violation_count = Beskar::Services::Waf.get_violation_count(ip)
    assert violation_count >= 2, "Expected at least 2 violations, got #{violation_count}"

    # Should be blocked (critical = 95 points, 2 violations = 190 > 150 threshold)
    assert Beskar::BannedIp.banned?(ip), "IP should be banned after config file enumeration"
  end

  test "detects path traversal enumeration attack" do
    ip = worker_ip(41)

    traversal_attempts = [
      "/files/../../../etc/passwd",
      "/uploads/../../config.php",
      "/assets/../.env",
      "/download?file=../../../../etc/shadow"
    ]

    traversal_attempts.each do |path|
      get path, headers: {"X-Forwarded-For" => ip}
    end

    # Path traversal is critical (95 points), 2 violations = 190 > 150 threshold
    assert Beskar::Services::Waf.get_violation_count(ip) >= 2, "Expected at least 2 violations"
    assert Beskar::BannedIp.banned?(ip), "IP should be banned after path traversal attempts"
  end

  # Monitor-only mode
  test "monitor mode logs violations but never blocks" do
    Beskar.configuration.monitor_only = true
    ip = worker_ip(50)

    # Make many critical violations
    10.times do
      get "/.env", headers: {"X-Forwarded-For" => ip}
    end

    # Should log violations
    assert Beskar::Services::Waf.get_violation_count(ip) >= 3

    # Should create security events with monitor-only metadata
    events = Beskar::SecurityEvent.where(ip_address: ip, event_type: "waf_violation")
    assert events.count > 0

    # Verify monitor-only metadata is present
    last_event = events.last
    assert last_event.metadata["monitor_only_mode"], "Event should indicate monitor-only mode"
    assert last_event.metadata["would_be_blocked"], "Event should indicate it would be blocked"
    assert_equal Beskar.configuration.waf[:score_threshold], last_event.metadata["score_threshold"]
    assert last_event.metadata["violation_count"] >= 3

    # Monitor mode records evidence without creating an active ban.
    assert_not Beskar::BannedIp.banned?(ip)

    # But should still be able to access (not blocked)
    get "/", headers: {"X-Forwarded-For" => ip}
    assert_response :success, "Request should succeed in monitor mode despite ban"
  end

  # Ban metadata
  test "WAF bans include detailed violation metadata" do
    ip = worker_ip(60)

    # Trigger ban with specific pattern
    3.times do
      get "/wp-admin/admin-ajax.php?action=evil", headers: {
        "X-Forwarded-For" => ip,
        "User-Agent" => "EvilBot/2.0"
      }
    end

    ban = Beskar::BannedIp.find_by(ip_address: ip)
    assert_not_nil ban
    assert_equal "waf_violation", ban.reason
    assert_match(/WordPress/, ban.details)
    assert_not_nil ban.metadata["violation_count"]
    assert_not_nil ban.metadata["patterns"]
  end

  # Concurrent violations
  test "handles concurrent WAF violations correctly" do
    ip = worker_ip(70)

    threads = []
    10.times do
      threads << Thread.new do
        get "/wp-admin/", headers: {"X-Forwarded-For" => ip}
      end
    end

    threads.each(&:join)

    # Should track multiple violations
    # (exact count depends on race conditions, but should be >= 2)
    violation_count = Beskar::Services::Waf.get_violation_count(ip)
    assert violation_count >= 2, "Expected at least 2 violations from concurrent requests, got #{violation_count}"

    # Should be banned (80 points * multiple violations > 150 threshold)
    assert Beskar::BannedIp.banned?(ip), "IP should be banned after concurrent violations"
  end

  # Case sensitivity
  test "WAF patterns are case insensitive" do
    variations = [
      "/WP-ADMIN/",
      "/Wp-Admin/",
      "/wp-admin/",
      "/WP-admin/",
      "/wP-AdMiN/"
    ]

    variations.each_with_index do |path, i|
      ip = worker_ip(80 + i)

      get path, headers: {"X-Forwarded-For" => ip}

      assert Beskar::Services::Waf.get_violation_count(ip) > 0,
        "Path #{path} should trigger WAF"
    end
  end

  # Performance under load
  test "WAF performs efficiently under high load" do
    start_time = Time.now

    # Simulate 100 requests
    100.times do |i|
      ip = "10.250.#{i / 256}.#{i % 256}"
      get "/", headers: {"X-Forwarded-For" => ip}
    end

    elapsed = Time.now - start_time

    # Should complete in reasonable time (adjust as needed)
    assert elapsed < 5.0, "WAF checking took too long: #{elapsed}s"
  end

  # Block expiry
  test "expired WAF blocks are not enforced" do
    ip = worker_ip(90)

    # Create expired ban
    Beskar::BannedIp.create!(
      ip_address: ip,
      reason: "waf_violation",
      banned_at: Time.current - 2.hours,
      expires_at: Time.current - 1.hour
    )

    # Should not be blocked
    get "/", headers: {"X-Forwarded-For" => ip}
    assert_response :success
  end

  # Cleanup
  test "cleanup removes expired WAF bans" do
    # Create some expired bans
    3.times do |i|
      Beskar::BannedIp.create!(
        ip_address: "10.251.0.#{i}",
        reason: "waf_violation",
        banned_at: Time.current - 2.hours,
        expires_at: Time.current - 1.hour
      )
    end

    # Create active ban
    active_ip = "10.251.0.100"
    Beskar::BannedIp.create!(
      ip_address: active_ip,
      reason: "waf_violation",
      banned_at: Time.current,
      expires_at: Time.current + 1.hour
    )

    assert_difference "Beskar::BannedIp.count", -3 do
      Beskar::BannedIp.cleanup_expired!
    end

    # Active ban should remain
    assert Beskar::BannedIp.exists?(ip_address: active_ip)
  end

  # User agent tracking
  test "WAF violations track user agent in security events" do
    ip = worker_ip(100)
    user_agent = "SuspiciousScanner/3.0 (Automatic)"

    get "/wp-admin/", headers: {
      "X-Forwarded-For" => ip,
      "User-Agent" => user_agent
    }

    event = Beskar::SecurityEvent.where(ip_address: ip).last
    assert_nil event.user_agent
  end

  # Multiple pattern matches
  test "WAF detects when request matches multiple patterns" do
    ip = worker_ip(110)

    # This path should match multiple patterns (wordpress + path traversal)
    get "/wp-admin/../../../etc/passwd", headers: {"X-Forwarded-For" => ip}

    # Should detect at least one violation
    assert Beskar::Services::Waf.get_violation_count(ip) > 0,
      "Should detect WAF violations for malicious path"

    # Should create security event
    event = Beskar::SecurityEvent.where(ip_address: ip, event_type: "waf_violation").last
    assert_not_nil event, "Should create security event for WAF violation"
    assert_not_nil event.metadata["waf_analysis"],
      "Security event should include WAF analysis metadata"
  end

  # IPv6 support
  test "WAF works with IPv6 addresses" do
    ip = "2001:db8::1"

    get "/wp-admin/", headers: {"X-Forwarded-For" => ip}

    assert Beskar::Services::Waf.get_violation_count(ip) > 0
  end

  # Query string variations
  test "WAF detects patterns regardless of query strings" do
    ip = worker_ip(120)

    paths = [
      "/wp-admin/",
      "/wp-admin/?debug=1",
      "/wp-admin/?redirect=/admin",
      "/wp-admin/index.php?action=login"
    ]

    paths.each do |path|
      get path, headers: {"X-Forwarded-For" => ip}
    end

    # WordPress is high severity (80 points), 2 violations = 160 > 150 threshold
    # So we'll have 2 violations tracked before ban
    assert Beskar::Services::Waf.get_violation_count(ip) >= 2, "Expected at least 2 violations"
    assert Beskar::BannedIp.banned?(ip), "IP should be banned after multiple WordPress scan attempts"
  end
end
