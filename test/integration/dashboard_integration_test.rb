require "test_helper"

module Beskar
  class DashboardIntegrationTest < ActionDispatch::IntegrationTest
    include Engine.routes.url_helpers
    include FactoryBot::Syntax::Methods

    setup do
      # Clear any existing data
      Beskar::SecurityEvent.delete_all
      Beskar::BannedIp.destroy_all

      # Configure authentication to allow access for tests
      Beskar.configuration.authenticate_admin = ->(_request) { true }
      Beskar.configuration.audit_actor = ->(_) { "test:administrator" }

      # Create test users
      @admin_user = create(:user, email_address: "admin@example.com")
      @regular_user = create(:user, email_address: "user@example.com")

      # Set up the routes for the engine
      @routes = Engine.routes
    end

    teardown do
      # Reset configuration
      Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
    end

    # End-to-end authentication flow
    test "complete authentication flow for dashboard access" do
      # Configure authentication to check for admin session
      admin_authenticated = false
      Beskar.configuration.authenticate_admin = lambda do |request|
        admin_authenticated
      end

      # Try to access dashboard without authentication - returns 404 to avoid revealing Beskar is installed
      get "/beskar/dashboard"
      assert_response :not_found

      # Simulate admin login
      admin_authenticated = true

      # Now can access dashboard
      get "/beskar/dashboard"
      assert_response :success
      assert_select "h1", text: /Security Dashboard/i
    end

    # Complete dashboard navigation flow
    test "navigates through all dashboard sections" do
      setup_realistic_data

      # Start at main dashboard
      get "/beskar/dashboard"
      assert_response :success
      assert_select "h1", text: /Security Dashboard/i

      # Navigate to security events
      assert_select "a[href='/beskar/security_events']" do |links|
        get links.first["href"]
      end
      assert_response :success
      assert_select "h1", text: /Security Events/i

      # Navigate to specific event
      event = Beskar::SecurityEvent.first
      get "/beskar/security_events/#{event.id}"
      assert_response :success
      assert_select "h1", text: /Security Event ##{event.id}/

      # Navigate to banned IPs
      get "/beskar/banned_ips"
      assert_response :success
      assert_select "h1", text: /Banned IPs/i

      # Navigate back to dashboard
      get "/beskar/dashboard"
      assert_response :success
    end

    # Complete flow: Detect threat → Review → Ban
    test "threat detection to ban workflow" do
      # Simulate multiple failed login attempts from same IP
      attacker_ip = "192.168.100.50"
      5.times do |i|
        create(:security_event,
          event_type: "login_failure",
          ip_address: attacker_ip,
          risk_score: 70 + i * 5,
          created_at: (5 - i).minutes.ago,
          metadata: {attempted_email: "admin@example.com"})
      end

      # View dashboard and see the threat
      get "/beskar/dashboard"
      assert_response :success

      # Threat IP should appear in top threats section
      assert_match attacker_ip, response.body

      # Ban via the form
      assert_difference "Beskar::BannedIp.count", 1 do
        post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                            banned_ip: {
                                              ip_address: attacker_ip,
                                              reason: "Multiple failed login attempts"
                                            },
                                            ban_type: "temporary",
                                            duration: "86400"} # 24 hours in seconds
      end

      ban = Beskar::BannedIp.find_by(ip_address: attacker_ip)
      assert_redirected_to "/beskar/banned_ips/#{ban.id}"

      # Verify ban was created
      assert ban
      assert_equal "Multiple failed login attempts", ban.reason
      assert ban.active?

      # Check dashboard reflects the ban
      get "/beskar/dashboard"
      assert_response :success
      assert_select ".stat-label", text: /Blocked IPs/i do |elements|
        # Find the parent card and check the value
        card = elements.first.parent
        assert card.text.include?("1")
      end
    end

    # Complete flow: Monitor → Filter → Export
    test "security event monitoring and analysis workflow" do
      # Create diverse security events
      create_list(:security_event, 5, :high_risk, created_at: 1.hour.ago)
      create_list(:security_event, 3, :critical_risk, created_at: 1.hour.ago)
      create_list(:security_event, 5, :login_success, risk_score: 10, created_at: 1.hour.ago)

      # Start at events page
      get "/beskar/security_events"
      assert_response :success

      # Apply filters to find high-risk events
      get "/beskar/security_events", params: {
        risk_level: "high",
        time_range: "last_24h"
      }
      assert_response :success

      # Should see high risk badge (danger class for high-risk events 61-85)
      assert_select ".badge-danger"

      # Filter by specific IP showing suspicious activity
      suspicious_ip = "203.0.113.1"
      create(:security_event, ip_address: suspicious_ip, risk_score: 75)

      get "/beskar/security_events", params: {
        ip_address: suspicious_ip
      }
      assert_response :success
      assert_match suspicious_ip, response.body

      # Export filtered results as CSV
      get "/beskar/security_events/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {
        ip_address: suspicious_ip
      }
      assert_response :success
      assert_equal "text/csv", response.content_type

      # Verify CSV contains filtered data
      csv_content = response.body
      assert csv_content.include?(suspicious_ip)
    end

    # Complete ban management workflow
    test "comprehensive IP ban management workflow" do
      # Create an active ban
      ban = create(:banned_ip,
        ip_address: "192.168.50.1",
        reason: "Initial violation",
        expires_at: 1.hour.from_now,
        violation_count: 1)

      # View ban details
      get "/beskar/banned_ips/#{ban.id}"
      assert_response :success
      assert_match(/192.168.50.1/, response.body)

      # An administrative extension changes time, not the violation count.
      post "/beskar/banned_ips/#{ban.id}/extend", params: {audit_reason: "Reviewed test case", duration: "24h"}
      assert_redirected_to "/beskar/banned_ips/#{ban.id}"

      ban.reload
      assert_equal 1, ban.violation_count
      assert ban.expires_at > 1.hour.from_now

      # After multiple violations, make it permanent
      4.times { ban.extend_ban! }

      get "/beskar/banned_ips/#{ban.reload.id}"
      assert_response :success
      assert_match(/Permanent/i, response.body)

      # Later, decide to unban
      delete "/beskar/banned_ips/#{ban.id}", params: {audit_reason: "Reviewed test case"}
      assert_redirected_to "/beskar/banned_ips"

      # Verify IP is no longer banned
      assert_not Beskar::BannedIp.banned?(ban.ip_address)
    end

    # Test dashboard with realistic data patterns
    test "dashboard performance with realistic security patterns" do
      # Create realistic attack patterns
      create_brute_force_pattern("192.168.1.100", 1.hour.ago)
      create_sql_injection_pattern("203.0.113.50", 2.hours.ago)
      create_bot_scan_pattern("185.220.101.1", 30.minutes.ago)
      create_normal_traffic_pattern(3.hours.ago)

      # Load dashboard
      start_time = Time.current
      get "/beskar/dashboard"
      load_time = Time.current - start_time

      assert_response :success
      assert load_time < 1.second, "Dashboard too slow with realistic data: #{load_time}s"

      # Verify statistics are accurate
      assert_select ".stat-card" do |cards|
        # Check that we have reasonable counts
        total_events_card = cards.find { |c| c.text.include?("Total Events") }
        assert total_events_card

        # Should have events from all patterns (20 brute force + 3 SQL injection + 5 bot scan + 10 normal = 38)
        total_count = total_events_card.text.match(/\d+/)[0].to_i
        assert total_count >= 38, "Expected at least 38 events, got #{total_count}"
      end

      # Check risk distribution is displayed
      assert_select ".card-title", text: /Risk Distribution/i

      # Verify top threats section exists and shows the brute force IP
      assert_select ".card-title", text: /Top Threat IPs/i
      assert_match(/192.168.1.100/, response.body)
    end

    # Test filtering and search across dashboard
    test "search and filter workflow across dashboard sections" do
      # Clear any existing events
      Beskar::SecurityEvent.delete_all

      # Create events with searchable patterns
      create(:security_event,
        ip_address: "10.0.0.1",
        metadata: {details: "Suspicious user agent: sqlmap"})
      create(:security_event,
        ip_address: "10.0.0.2",
        metadata: {details: "Normal browsing activity"})

      # Search for SQL injection indicators
      get "/beskar/security_events", params: {search: "sqlmap"}
      assert_response :success
      # Check that we found the event with sqlmap in metadata
      assert_match(/sqlmap/, response.body)

      # Use time range filter
      Beskar::SecurityEvent.delete_all
      create(:security_event, created_at: 25.hours.ago)
      create(:security_event, created_at: 1.hour.ago)

      get "/beskar/dashboard", params: {time_range: "24h"}
      assert_response :success

      # Should show some events
      assert_response :success
    end

    # Test bulk operations workflow
    test "bulk operations on banned IPs" do
      # Create mix of expired and active bans
      active_bans = create_list(:banned_ip, 3, :active)
      create_list(:banned_ip, 5, :expired)

      # View all bans
      get "/beskar/banned_ips"
      assert_response :success

      # Test bulk unban action
      assert_difference "Beskar::BannedIp.count", -2 do
        post "/beskar/banned_ips/bulk_action", params: {audit_reason: "Reviewed test case",
                                                        bulk_action: "unban",
                                                        ip_ids: [active_bans[0].id, active_bans[1].id]}
      end
      assert_redirected_to "/beskar/banned_ips"

      # Test bulk extend action
      post "/beskar/banned_ips/bulk_action", params: {audit_reason: "Reviewed test case",
                                                      bulk_action: "extend",
                                                      duration: "24h",
                                                      ip_ids: [active_bans[2].id]}
      assert_redirected_to "/beskar/banned_ips"

      active_bans[2].reload
      assert_equal 1, active_bans[2].violation_count
    end

    # Test real-time threat response workflow
    test "real-time threat detection and response" do
      # Simulate ongoing attack
      attacker_ip = "192.168.200.1"

      # Initial suspicious activity
      2.times do
        create(:security_event,
          event_type: "login_failure",
          ip_address: attacker_ip,
          risk_score: 40,
          created_at: 10.minutes.ago)
      end

      # Check dashboard shows moderate threat
      get "/beskar/dashboard"
      assert_response :success

      # Continue attack with escalation
      3.times do
        create(:security_event,
          event_type: "waf_violation",
          ip_address: attacker_ip,
          risk_score: 85,
          created_at: 2.minutes.ago)
      end

      # Refresh dashboard - threat should be prominent
      get "/beskar/dashboard", params: {time_range: "1h"}
      assert_response :success

      # High risk events should be visible
      assert_select ".stat-label", text: /High Risk/i do |elements|
        card = elements.first.parent
        count = card.text.match(/\d+/)[0].to_i
        assert count >= 3
      end

      # Take immediate action - ban the IP
      post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                          banned_ip: {
                                            ip_address: attacker_ip,
                                            reason: "WAF violations after failed logins"
                                          },
                                          ban_type: "permanent"}

      # Verify IP is now banned
      assert Beskar::BannedIp.banned?(attacker_ip)
      ban = Beskar::BannedIp.find_by(ip_address: attacker_ip)
      assert ban.permanent?
    end

    # Test dashboard with different user permissions
    test "dashboard access with different authentication levels" do
      # Test without authentication - should use default (allow all in tests)
      get "/beskar/dashboard"
      assert_response :success

      # Test with authentication that denies access
      Beskar.configuration.authenticate_admin = lambda do |request|
        false # Deny all access
      end

      # Non-admin cannot access - returns 404 to avoid revealing Beskar is installed
      get "/beskar/dashboard"
      assert_response :not_found

      # Test with authentication that allows access
      Beskar.configuration.authenticate_admin = lambda do |request|
        true # Allow access
      end

      # Admin can access
      get "/beskar/dashboard"
      assert_response :success

      # Can perform actions as admin
      post "/beskar/banned_ips",
        params: {
          audit_reason: "Reviewed test case",
          banned_ip: {
            ip_address: "10.0.0.1",
            reason: "Admin ban"
          },
          ban_type: "temporary",
          duration: "3600" # 1 hour in seconds
        }

      assert_response :redirect
      assert Beskar::BannedIp.banned?("10.0.0.1")
    end

    # Test error handling throughout workflow
    test "graceful error handling in dashboard workflow" do
      # Try to ban without required reason
      post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                          banned_ip: {
                                            ip_address: "10.0.0.1"
                                          }}
      # Should render form again due to validation error
      assert_response :unprocessable_content # renders :new template

      # Try to access non-existent event
      get "/beskar/security_events/999999"
      assert_response :not_found

      # Dashboard should still work with no data
      Beskar::SecurityEvent.delete_all
      Beskar::BannedIp.destroy_all

      get "/beskar/dashboard"
      assert_response :success
      # Check for zero stat values
      assert_match(/0/, response.body)
    end

    # Test dashboard data consistency
    test "dashboard data remains consistent across sections" do
      # Create known dataset
      Beskar::SecurityEvent.delete_all
      Beskar::BannedIp.destroy_all

      create_list(:security_event, 10, created_at: 1.hour.ago)
      create_list(:security_event, 3, :high_risk, created_at: 1.hour.ago)
      create_list(:banned_ip, 5, :active)

      # Get counts from dashboard
      get "/beskar/dashboard"
      assert_response :success

      # Extract displayed counts
      dashboard_total = extract_stat_value("Total Events")
      dashboard_high_risk = extract_stat_value("High Risk")
      dashboard_blocked = extract_stat_value("Blocked IPs")

      # Verify counts match actual data
      assert_equal 13, dashboard_total
      assert_equal 3, dashboard_high_risk
      assert_equal 5, dashboard_blocked

      # Navigate to events page
      get "/beskar/security_events"
      assert_response :success
      # Events should be displayed in table
      assert_match(/security_event/, response.body)

      # Navigate to banned IPs page
      get "/beskar/banned_ips"
      assert_response :success
      # Should show the banned IPs
      assert_select "tbody tr", minimum: 5
    end

    private

    def setup_realistic_data
      # Create variety of security events
      create_list(:security_event, 5, :login_success, created_at: 2.hours.ago)
      create_list(:security_event, 3, :login_failure, created_at: 1.hour.ago)
      create_list(:security_event, 2, :high_risk, created_at: 30.minutes.ago)
      create(:security_event, :critical_risk, created_at: 10.minutes.ago)

      # Create some banned IPs
      create(:banned_ip, :active)
      create(:banned_ip, :permanent)
      create(:banned_ip, :expired)
    end

    def create_brute_force_pattern(ip, start_time)
      20.times do |i|
        create(:security_event,
          event_type: "login_failure",
          ip_address: ip,
          risk_score: 60 + i,
          created_at: start_time + i.minutes,
          metadata: {
            attempted_email: ["admin", "root", "administrator"][i % 3] + "@example.com",
            details: "Failed login attempt #{i + 1}"
          })
      end
    end

    def create_sql_injection_pattern(ip, start_time)
      payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "UNION SELECT * FROM passwords"]

      payloads.each_with_index do |payload, i|
        create(:security_event,
          event_type: "waf_violation",
          ip_address: ip,
          risk_score: 85 + i * 5,
          created_at: start_time + (i * 5).minutes,
          metadata: {
            waf_rule: "sql_injection",
            payload: payload,
            path: "/api/search",
            details: "SQL injection attempt detected"
          })
      end
    end

    def create_bot_scan_pattern(ip, start_time)
      paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config.php"]

      paths.each_with_index do |path, i|
        create(:security_event,
          event_type: "suspicious_request",
          ip_address: ip,
          risk_score: 70,
          created_at: start_time + i.seconds,
          user_agent: "BadBot/1.0",
          metadata: {
            path: path,
            details: "Automated scan detected",
            bot_detected: true
          })
      end
    end

    def create_normal_traffic_pattern(start_time)
      10.times do |i|
        create(:security_event,
          event_type: "login_success",
          ip_address: "192.168.1.#{i + 1}",
          risk_score: rand(5..15),
          created_at: start_time + (i * 10).minutes,
          user: @regular_user,
          metadata: {
            details: "Normal user activity"
          })
      end
    end

    def extract_stat_value(label)
      stat_card = css_select(".stat-card").find { |card| card.text.include?(label) }
      return 0 unless stat_card

      value_text = stat_card.css(".stat-value").text
      value_text.scan(/\d+/).first.to_i
    end

    def css_select(selector)
      Nokogiri::HTML(response.body).css(selector)
    end

    def flash
      return {} unless @controller
      @controller.flash
    end
  end
end
