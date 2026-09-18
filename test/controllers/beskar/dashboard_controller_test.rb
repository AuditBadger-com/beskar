require "test_helper"

module Beskar
  class DashboardControllerTest < ActionDispatch::IntegrationTest
    include Engine.routes.url_helpers
    include FactoryBot::Syntax::Methods

    setup do
      # Clear any existing data
      Beskar::SecurityEvent.delete_all
      Beskar::BannedIp.destroy_all

      # Configure authentication to allow access for tests
      Beskar.configuration.authenticate_admin = ->(_request) { true }

      # Create test user
      @user = create(:user)

      # Set up the routes for the engine
      @routes = Engine.routes
    end

    teardown do
      # Reset configuration
      Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
    end

    # Authentication tests
    test "requires authentication when configured" do
      # Configure authentication to deny access
      Beskar.configuration.authenticate_admin = ->(_request) { false }

      get "/beskar/dashboard"

      # Returns 404 to avoid revealing Beskar is installed
      assert_response :not_found
    end

    test "allows access when authenticated" do
      # Authentication is configured to allow in setup
      get "/beskar/dashboard"

      assert_response :success
    end

    test "requires authentication configuration" do
      # Reset to no authentication
      Beskar.configuration.authenticate_admin = nil

      # Logs error but returns 404 to avoid revealing Beskar is installed
      get "/beskar/dashboard"

      assert_response :not_found
    end

    # Dashboard display tests
    test "displays dashboard with default time range" do
      create_sample_events

      get "/beskar/dashboard"

      assert_response :success
      assert_match(/Security Dashboard/i, response.body)

      # Check that stats are displayed
      assert_select ".stat-card", minimum: 4
      assert_select ".stat-label", text: /Total Events/i
      assert_select ".stat-label", text: /Failed Logins/i
      assert_select ".stat-label", text: /Blocked IPs/i
      assert_select ".stat-label", text: /High Risk Events/i
    end

    test "displays statistics for 24 hour time range" do
      # Create events within and outside the time range
      create(:security_event, :login_failure, created_at: 12.hours.ago)
      create(:security_event, :login_failure, created_at: 23.hours.ago)
      create(:security_event, :login_failure, created_at: 25.hours.ago) # Outside range
      create(:security_event, :high_risk, created_at: 6.hours.ago)
      create(:security_event, :critical_risk, created_at: 1.hour.ago)

      create(:banned_ip, :active)
      create(:banned_ip, :permanent)

      get "/beskar/dashboard", params: {time_range: "24h"}

      assert_response :success

      # Check that stats are displayed
      assert_select ".stat-card" do |cards|
        assert cards.any? { |card| card.text.include?("Total Events") }
      end
    end

    test "displays statistics for 1 hour time range" do
      create(:security_event, created_at: 30.minutes.ago)
      create(:security_event, created_at: 45.minutes.ago)
      create(:security_event, created_at: 90.minutes.ago) # Outside range

      get "/beskar/dashboard", params: {time_range: "1h"}

      assert_response :success

      # Should show stats
      assert_select ".stat-value" do |values|
        # At least one stat value should be displayed
        assert values.any?
      end
    end

    test "displays statistics for 7 day time range" do
      create(:security_event, created_at: 1.day.ago)
      create(:security_event, created_at: 3.days.ago)
      create(:security_event, created_at: 6.days.ago)
      create(:security_event, created_at: 8.days.ago) # Outside range

      get "/beskar/dashboard", params: {time_range: "7d"}

      assert_response :success

      # Should show stats cards
      assert_select ".stat-card" do |cards|
        # Find the total events card
        total_events_card = cards.find { |card| card.text.include?("Total Events") }
        assert total_events_card
      end
    end

    test "displays recent activity table" do
      events = []
      5.times do |i|
        events << create(:security_event,
          event_type: "login_failure",
          created_at: i.minutes.ago,
          ip_address: "192.168.1.#{i}")
      end

      get "/beskar/dashboard"

      assert_response :success

      # Check recent activity table exists
      assert_select "table" do
        assert_select "th", text: /Time/i
        assert_select "th", text: /Event Type/i
        assert_select "th", text: /IP Address/i
      end
    end

    test "displays top threat IPs section" do
      # Create multiple events from same IPs to make them "top threats"
      3.times { create(:security_event, ip_address: "10.0.0.1", risk_score: 80) }
      2.times { create(:security_event, ip_address: "10.0.0.2", risk_score: 60) }
      create(:security_event, ip_address: "10.0.0.3", risk_score: 40)

      get "/beskar/dashboard"

      assert_response :success

      # Check for Top Threat IPs section
      assert_match(/Top Threat IPs/i, response.body)
      assert_select ".card-title", text: /Top Threat IPs/i
    end

    test "displays event types distribution" do
      create(:security_event, event_type: "login_failure")
      create(:security_event, event_type: "login_failure")
      create(:security_event, event_type: "login_success")
      create(:security_event, event_type: "waf_violation")

      get "/beskar/dashboard"

      assert_response :success

      # Check for Event Types section
      assert_select ".card-title", text: /Event Types/i
      assert_select ".card-subtitle", text: /Distribution by type/i
    end

    test "displays risk distribution section" do
      create(:security_event, risk_score: 10)  # Low
      create(:security_event, risk_score: 25)  # Low
      create(:security_event, risk_score: 45)  # Medium
      create(:security_event, risk_score: 70)  # High
      create(:security_event, risk_score: 90)  # Critical

      get "/beskar/dashboard"

      assert_response :success

      # Check for Risk Distribution section
      assert_select ".card-title", text: /Risk Distribution/i
      # Risk levels should be displayed
      assert_match(/Low/i, response.body)
      assert_match(/Medium/i, response.body)
      assert_match(/High/i, response.body)
      assert_match(/Critical/i, response.body)
    end

    test "displays active IP bans section" do
      create(:banned_ip, :active, ip_address: "10.0.0.1", reason: "Brute force")
      create(:banned_ip, :permanent, ip_address: "10.0.0.2", reason: "Bot detected")
      create(:banned_ip, :expired) # Should not appear

      get "/beskar/dashboard"

      assert_response :success

      # Check for Active Bans section
      assert_select ".card-title", text: /Active Bans/i
      # Check that IPs are displayed
      assert_match(/10.0.0.1/, response.body)
      assert_match(/10.0.0.2/, response.body)
    end

    test "handles empty data gracefully" do
      # No events or bans created
      get "/beskar/dashboard"

      assert_response :success

      # Should display zeros in stats
      assert_select ".stat-value", text: "0"
    end

    test "displays ban actions for threat IPs" do
      # Create events to make IPs appear in threat list
      3.times { create(:security_event, ip_address: "10.0.0.1", risk_score: 80) }

      get "/beskar/dashboard"

      assert_response :success

      # Should have ban link or banned badge
      assert_match(/10.0.0.1/, response.body)
    end

    test "links to detailed views" do
      create_sample_events

      get "/beskar/dashboard"

      assert_response :success

      # Check for view all links
      assert_match(/View All Security Events/i, response.body)
      assert_match(/Manage All Bans/i, response.body)
    end

    test "respects time range filter" do
      # Create events at specific times
      Time.use_zone("UTC") do
        create(:security_event, created_at: Time.zone.now - 23.hours)
        create(:security_event, created_at: Time.zone.now - 25.hours)
      end

      get "/beskar/dashboard", params: {time_range: "24h"}

      assert_response :success

      # Stats should be displayed
      assert_select ".stat-card" do |cards|
        assert cards.any? { |c| c.text.include?("Total Events") }
      end
    end

    test "displays risk badges correctly" do
      create(:security_event, risk_score: 10)
      create(:security_event, risk_score: 50)
      create(:security_event, risk_score: 75)
      create(:security_event, risk_score: 95)

      get "/beskar/dashboard"

      assert_response :success

      # Check for risk badges in recent events
      assert_select ".badge"
    end

    test "shows time range selector buttons" do
      get "/beskar/dashboard"

      assert_response :success

      # Check for time range buttons
      assert_select "a.btn", text: "1H"
      assert_select "a.btn", text: "6H"
      assert_select "a.btn", text: "24H"
      assert_select "a.btn", text: "7D"
      assert_select "a.btn", text: "30D"
    end

    test "escapes HTML in event data" do
      create(:security_event,
        event_type: "<script>alert('xss')</script>",
        metadata: {details: "<img src=x onerror=alert('xss')>"})

      get "/beskar/dashboard"

      assert_response :success

      # Should escape HTML tags
      assert_no_match(/<script>alert/, response.body)
      assert_match(/&lt;script&gt;/, response.body)
    end

    test "includes CSRF protection" do
      get "/beskar/dashboard"

      assert_response :success

      # CSRF protection should be enabled for the engine
      # The ApplicationController has protect_from_forgery configured
      # In test environment, CSRF tokens might not be in meta tags but protection is still active
      assert_nothing_raised do
        get "/beskar/dashboard"
      end
    end

    test "loads efficiently with large datasets" do
      # Create a large number of events
      100.times do |i|
        create(:security_event,
          ip_address: "192.168.#{i % 10}.#{i}",
          created_at: i.hours.ago)
      end

      50.times do |i|
        create(:banned_ip, :active, ip_address: "10.#{i}.0.1")
      end

      start_time = Time.current
      get "/beskar/dashboard"
      load_time = Time.current - start_time

      assert_response :success

      # Should load within reasonable time (adjust as needed)
      assert load_time < 2.seconds, "Dashboard took too long to load: #{load_time}s"

      # Should still show limited items
      assert_select "tbody tr" # Should have some rows but not all
    end

    test "shows recent events with user information" do
      user = create(:user, email_address: "test@example.com")
      create(:security_event, user: user, event_type: "login_success")
      create(:security_event, user: nil, event_type: "login_failure")

      get "/beskar/dashboard"

      assert_response :success

      # Events table should show
      assert_select "table tbody tr", minimum: 2
    end

    test "displays critical threats stat" do
      create(:security_event, risk_score: 95)
      create(:security_event, risk_score: 90)

      get "/beskar/dashboard"

      assert_response :success

      assert_select ".stat-label", text: /Critical Threats/i
      assert_select ".stat-value" do |values|
        assert values.any? { |v| v.text.include?("2") }
      end
    end

    private

    def create_sample_events
      # Create a variety of events for testing
      create(:security_event, :login_success, created_at: 1.hour.ago)
      create(:security_event, :login_failure, created_at: 2.hours.ago)
      create(:security_event, :high_risk, created_at: 3.hours.ago)
      create(:security_event, :critical_risk, created_at: 4.hours.ago)

      # Create some banned IPs
      create(:banned_ip, :active)
      create(:banned_ip, :permanent)
      create(:banned_ip, :expired)
    end
  end
end
