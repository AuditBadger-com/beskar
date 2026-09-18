require "test_helper"
require "ostruct"

class WafExceptionIntegrationTest < ActionDispatch::IntegrationTest
  def setup
    Rails.cache.clear
    Beskar::BannedIp.destroy_all
    Beskar::SecurityEvent.delete_all

    # Save original configuration
    @original_waf = Beskar.configuration.waf.dup
    @original_monitor_only = Beskar.configuration.monitor_only
    @original_ip_whitelist = Beskar.configuration.ip_whitelist.dup

    # Enable WAF with exception detection
    Beskar.configuration.waf = {
      enabled: true,
      exception_detection: :all, # Exercise the opt-in broad exception adapter.
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
      max_violations_tracked: 50,
      record_not_found_exclusions: [
        %r{/posts/.*},
        %r{/articles/\d+}
      ]
    }
    Beskar.configuration.monitor_only = false
    Beskar.configuration.ip_whitelist = []
    # Clear IpWhitelist cache after changing configuration
    Beskar::Services::IpWhitelist.clear_cache!
  end

  def teardown
    Rails.cache.clear
    Beskar::BannedIp.destroy_all
    Beskar::SecurityEvent.delete_all

    # Restore original configuration
    Beskar.configuration.waf = @original_waf
    Beskar.configuration.monitor_only = @original_monitor_only
    Beskar.configuration.ip_whitelist = @original_ip_whitelist
    # Clear IpWhitelist cache after restoring configuration
    Beskar::Services::IpWhitelist.clear_cache!
  end

  test "middleware catches UnknownFormat exception and records WAF violation" do
    # Mock the application to raise UnknownFormat
    app = ->(_env) { raise ActionController::UnknownFormat.new("Unknown format requested") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    # Create request that would trigger UnknownFormat
    # Note: /api/users/123.exe will match both the path pattern AND the exception
    env = Rack::MockRequest.env_for(
      "/api/users/123.exe",
      "REMOTE_ADDR" => "192.168.1.100",
      "HTTP_USER_AGENT" => "Scanner/1.0"
    )

    # The middleware should catch the exception, record it, and re-raise
    assert_raises(ActionController::UnknownFormat) do
      middleware.call(env)
    end

    # The same request is charged once, even if the application also raises.
    assert_equal 1, Beskar::SecurityEvent.count
    exception_event = Beskar::SecurityEvent.last
    assert_not_nil exception_event
    assert_equal "waf_violation", exception_event.event_type
    assert_equal "192.168.1.100", exception_event.ip_address
    assert_equal 60, exception_event.risk_score # Medium severity
    assert_equal "rails_exceptions", exception_event.metadata["waf_analysis"]["patterns"].first["category"]
  end

  test "middleware catches IP spoofing exception as critical threat" do
    # Mock the application to raise IP spoofing error
    app = ->(_env) { raise ActionDispatch::RemoteIp::IpSpoofAttackError.new("IP spoofing attack?!") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    env = Rack::MockRequest.env_for(
      "/admin/dashboard",
      "REMOTE_ADDR" => "192.168.1.101",
      "HTTP_USER_AGENT" => "Attacker/1.0"
    )

    # The middleware should catch and re-raise
    assert_raises(ActionDispatch::RemoteIp::IpSpoofAttackError) do
      middleware.call(env)
    end

    # Verify critical severity was recorded
    event = Beskar::SecurityEvent.last
    assert_equal "waf_violation", event.event_type
    assert_equal 95, event.risk_score # Critical severity
    assert_equal "ActionDispatch::RemoteIp::IpSpoofAttackError", event.metadata["waf_analysis"]["exception_class"]
  end

  test "middleware catches RecordNotFound and respects exclusion patterns" do
    # Mock app that raises RecordNotFound
    app = ->(_env) { raise ActiveRecord::RecordNotFound.new("Couldn't find Post") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    # Test excluded path - should NOT create security event
    env = Rack::MockRequest.env_for(
      "/posts/non-existent-slug",
      "REMOTE_ADDR" => "192.168.1.102"
    )

    assert_raises(ActiveRecord::RecordNotFound) do
      middleware.call(env)
    end
    assert_equal 0, Beskar::SecurityEvent.count, "Excluded path should not create security event"

    # Test non-excluded path - SHOULD create security event
    env = Rack::MockRequest.env_for(
      "/admin/users/999999",
      "REMOTE_ADDR" => "192.168.1.102"
    )

    assert_raises(ActiveRecord::RecordNotFound) do
      middleware.call(env)
    end
    assert_equal 1, Beskar::SecurityEvent.count, "Non-excluded path should create security event"

    event = Beskar::SecurityEvent.last
    assert_equal 30, event.risk_score # Low severity
    assert_equal "ActiveRecord::RecordNotFound", event.metadata["waf_analysis"]["exception_class"]
  end

  test "accumulating exception violations triggers auto-block" do
    app = ->(_env) { raise ActionController::UnknownFormat.new("Unknown format") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    attacker_ip = "192.168.1.103"

    # Generate 3 violations to trigger ban
    3.times do |i|
      env = Rack::MockRequest.env_for(
        "/api/endpoint#{i}.exe",
        "REMOTE_ADDR" => attacker_ip
      )

      assert_raises(ActionController::UnknownFormat) do
        middleware.call(env)
      end
    end

    # IP should be banned after 3 violations
    assert Beskar::BannedIp.banned?(attacker_ip)
    banned = Beskar::BannedIp.find_by(ip_address: attacker_ip)
    assert_equal "waf_violation", banned.reason
    assert_includes banned.details, "Unknown format requested"

    # Next request should be blocked (not just exception raised)
    normal_app = ->(_env) { [200, {}, ["OK"]] }
    middleware = Beskar::Middleware::RequestAnalyzer.new(normal_app)

    env = Rack::MockRequest.env_for(
      "/normal/path",
      "REMOTE_ADDR" => attacker_ip
    )

    status, headers, _body = middleware.call(env)
    assert_equal 403, status
    assert_equal "true", headers["x-beskar-blocked"]
  end

  test "monitor-only mode logs exceptions but doesn't block" do
    Beskar.configuration.monitor_only = true

    # Create 3 violations
    app = ->(_env) { raise ActionController::UnknownFormat.new("Unknown format") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    attacker_ip = "192.168.1.104"

    3.times do |i|
      env = Rack::MockRequest.env_for(
        "/api/test#{i}.bat",
        "REMOTE_ADDR" => attacker_ip
      )

      assert_raises(ActionController::UnknownFormat) do
        middleware.call(env)
      end
    end

    # Monitor observations must not create active bans.
    assert_not Beskar::BannedIp.banned?(attacker_ip)

    # But subsequent requests should NOT be blocked in monitor-only mode
    normal_app = ->(_env) { [200, {}, ["OK"]] }
    middleware = Beskar::Middleware::RequestAnalyzer.new(normal_app)

    env = Rack::MockRequest.env_for(
      "/normal/path",
      "REMOTE_ADDR" => attacker_ip
    )

    status, _headers, _body = middleware.call(env)
    assert_equal 200, status, "Should not block in monitor-only mode"

    # Check that events have monitor-only flag
    events = Beskar::SecurityEvent.where(ip_address: attacker_ip)
    events.each do |event|
      assert event.metadata["monitor_only_mode"]
    end
  end

  test "whitelisted IPs log exceptions but are never blocked" do
    whitelisted_ip = "192.168.1.205"  # Use unique IP to avoid conflicts

    # Ensure clean state for this test
    Rails.cache.clear
    Beskar::Services::Waf.reset_violations(whitelisted_ip)
    Beskar::BannedIp.unban!(whitelisted_ip) if Beskar::BannedIp.banned?(whitelisted_ip)

    # Set whitelist explicitly for this test
    Beskar.configuration.ip_whitelist = [whitelisted_ip]
    # Clear cache to ensure new whitelist is recognized
    Beskar::Services::IpWhitelist.clear_cache!

    # Verify IP is actually whitelisted
    assert Beskar::Services::IpWhitelist.whitelisted?(whitelisted_ip), "IP should be whitelisted"

    # Directly test WAF violations without middleware complexity
    # First, test that violations are recorded but don't trigger bans
    request = OpenStruct.new(
      fullpath: "/test.exe",
      path: "/test.exe",
      ip: whitelisted_ip,
      user_agent: "Test"
    )

    exception = ActionController::UnknownFormat.new("Unknown format")

    # Record 5 violations from whitelisted IP
    5.times do
      analysis = Beskar::Services::Waf.analyze_exception(exception, request)
      if analysis
        Beskar::Services::Waf.record_violation(whitelisted_ip, analysis, whitelisted: true)
      end
    end

    # Should create security events
    assert Beskar::SecurityEvent.count >= 5

    # But should NOT be banned (whitelisted IPs are never auto-blocked)
    refute Beskar::BannedIp.banned?(whitelisted_ip), "Whitelisted IP should not be banned"

    # Clear violations before middleware test to start fresh
    Beskar::Services::Waf.reset_violations(whitelisted_ip)

    # Now test through middleware that exceptions still get raised
    app = ->(_env) { raise ActionController::UnknownFormat.new("Unknown format") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    env = Rack::MockRequest.env_for(
      "/another/test",
      "REMOTE_ADDR" => whitelisted_ip
    )

    # Check whitelist status is recognized by middleware
    request = ActionDispatch::Request.new(env)
    assert_equal whitelisted_ip, request.ip
    assert Beskar::Services::IpWhitelist.whitelisted?(request.ip), "Middleware should recognize whitelisted IP"

    # Exception should still be raised for whitelisted IPs
    assert_raises(ActionController::UnknownFormat) do
      middleware.call(env)
    end

    # Debug: Check violation count after middleware call
    violation_count = Beskar::Services::Waf.get_violation_count(whitelisted_ip)
    assert violation_count <= 2, "Should only have 1-2 violations (path + exception), got #{violation_count}"

    # Still should not be banned
    refute Beskar::BannedIp.banned?(whitelisted_ip), "Whitelisted IP should still not be banned after middleware call"
  end

  test "combines exception violations with regular WAF patterns" do
    attacker_ip = "192.168.1.106"

    # First, a regular WAF pattern violation
    normal_app = ->(_env) { [200, {}, ["OK"]] }
    middleware = Beskar::Middleware::RequestAnalyzer.new(normal_app)

    env = Rack::MockRequest.env_for(
      "/wp-admin",
      "REMOTE_ADDR" => attacker_ip
    )
    middleware.call(env)
    assert_equal 1, Beskar::Services::Waf.get_violation_count(attacker_ip)

    # Then an exception-based violation (using a path that won't double-match)
    exception_app = ->(_env) { raise ActionController::UnknownFormat.new("Unknown format") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(exception_app)

    env = Rack::MockRequest.env_for(
      "/normalpath",  # Simple path that won't match Rails exception patterns
      "REMOTE_ADDR" => attacker_ip
    )
    assert_raises(ActionController::UnknownFormat) do
      middleware.call(env)
    end
    assert_equal 2, Beskar::Services::Waf.get_violation_count(attacker_ip)

    # One more regular pattern to trigger ban
    middleware = Beskar::Middleware::RequestAnalyzer.new(normal_app)
    env = Rack::MockRequest.env_for(
      "/phpmyadmin",
      "REMOTE_ADDR" => attacker_ip
    )
    middleware.call(env)

    # Should be banned from combined violations
    assert Beskar::BannedIp.banned?(attacker_ip)

    # Verify we have both types of violations
    events = Beskar::SecurityEvent.where(ip_address: attacker_ip)
    exception_events = events.select { |e| e.metadata["waf_analysis"]["exception_class"].present? }
    regular_events = events.select { |e| e.metadata["waf_analysis"]["exception_class"].nil? }

    assert_equal 1, exception_events.count
    assert_equal 2, regular_events.count
  end

  test "different exception severities contribute different risk scores" do
    # Test Medium severity (UnknownFormat)
    app = ->(_env) { raise ActionController::UnknownFormat.new("Unknown format") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    env = Rack::MockRequest.env_for("/test.exe", "REMOTE_ADDR" => "192.168.1.107")
    assert_raises(ActionController::UnknownFormat) { middleware.call(env) }

    event = Beskar::SecurityEvent.last
    assert_equal 60, event.risk_score

    # Test Critical severity (IP Spoofing)
    app = ->(_env) { raise ActionDispatch::RemoteIp::IpSpoofAttackError.new("IP spoofing") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    env = Rack::MockRequest.env_for("/admin", "REMOTE_ADDR" => "192.168.1.108")
    assert_raises(ActionDispatch::RemoteIp::IpSpoofAttackError) { middleware.call(env) }

    event = Beskar::SecurityEvent.last
    assert_equal 95, event.risk_score

    # Test Low severity (RecordNotFound)
    app = ->(_env) { raise ActiveRecord::RecordNotFound.new("Not found") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    env = Rack::MockRequest.env_for("/users/999999", "REMOTE_ADDR" => "192.168.1.109")
    assert_raises(ActiveRecord::RecordNotFound) { middleware.call(env) }

    event = Beskar::SecurityEvent.last
    assert_equal 30, event.risk_score
  end

  test "WAF disabled does not catch exceptions" do
    Beskar.configuration.waf[:enabled] = false

    app = ->(_env) { raise ActionController::UnknownFormat.new("Unknown format") }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    env = Rack::MockRequest.env_for(
      "/test.exe",
      "REMOTE_ADDR" => "192.168.1.110"
    )

    # Exception should be raised but no security event created
    assert_raises(ActionController::UnknownFormat) do
      middleware.call(env)
    end

    assert_equal 0, Beskar::SecurityEvent.count
    assert_equal 0, Beskar::Services::Waf.get_violation_count("192.168.1.110")
  end
end
