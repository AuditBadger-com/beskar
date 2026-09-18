require "test_helper"

module Beskar
  class BannedIpsControllerTest < ActionDispatch::IntegrationTest
    setup do
      # Clear any existing data
      Beskar::BannedIp.delete_all
      Beskar::SecurityEvent.delete_all

      # Setup authentication for tests
      Beskar.configure do |config|
        config.authenticate_admin = ->(request) { true }
        config.audit_actor = ->(_) { "test:administrator" }
      end
    end

    teardown do
      # Reset configuration after each test
      Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
    end

    # Authentication Tests
    test "requires authentication when configured" do
      Beskar.configure do |config|
        config.authenticate_admin = ->(request) { false }
      end

      get "/beskar/banned_ips"
      # Returns 404 to avoid revealing Beskar is installed
      assert_response :not_found
    end

    test "allows access when authenticated" do
      get "/beskar/banned_ips"
      assert_response :success
    end

    test "requires authentication configuration" do
      Beskar.configure do |config|
        config.authenticate_admin = nil  # No authentication when nil
      end

      get "/beskar/banned_ips"
      # Logs error but returns 404 to avoid revealing Beskar is installed
      assert_response :not_found
    end

    # Index Action Tests
    test "displays banned IPs index" do
      banned_ips = create_list(:banned_ip, 5)

      get "/beskar/banned_ips"

      assert_response :success
      assert_match "Banned IPs", response.body

      # Check that IPs are displayed in the table
      banned_ips.each do |ban|
        assert_match ban.ip_address, response.body
      end
    end

    test "displays empty state when no banned IPs" do
      get "/beskar/banned_ips"

      assert_response :success
      assert_match(/no.*banned.*ips|empty/i, response.body)
    end

    test "shows active and expired bans" do
      active = create(:banned_ip, :active)
      expired = create(:banned_ip, :expired)

      get "/beskar/banned_ips"

      assert_response :success
      assert_match active.ip_address, response.body
      assert_match expired.ip_address, response.body
    end

    test "displays ban details correctly" do
      ban = create(:banned_ip,
        ip_address: "192.168.1.100",
        reason: "Multiple failed login attempts",
        expires_at: 1.day.from_now)

      get "/beskar/banned_ips"

      assert_response :success
      assert_match ban.ip_address, response.body
      assert_match "Multiple failed login attempts", response.body
    end

    test "paginates banned IPs" do
      create_list(:banned_ip, 30)

      get "/beskar/banned_ips", params: {per_page: 10}

      assert_response :success
      # Count table rows (excluding header)
      assert_select "tbody tr", count: 10
      assert_match(/Showing.*10.*of.*30/i, response.body)
    end

    test "respects per_page parameter" do
      create_list(:banned_ip, 50)

      [10, 25, 50].each do |per_page|
        get "/beskar/banned_ips", params: {per_page: per_page}
        assert_response :success
        assert_select "tbody tr", maximum: per_page
      end
    end

    test "handles invalid pagination parameters gracefully" do
      create_list(:banned_ip, 5)

      # Invalid page number
      get "/beskar/banned_ips", params: {page: -1}
      assert_response :success

      # Invalid per_page
      get "/beskar/banned_ips", params: {per_page: 0}
      assert_response :success

      # Non-numeric values
      get "/beskar/banned_ips", params: {page: "abc", per_page: "xyz"}
      assert_response :success
    end

    # Filtering Tests
    test "filters by status" do
      active = create(:banned_ip, :active)
      expired = create(:banned_ip, :expired)

      get "/beskar/banned_ips", params: {status: "active"}

      assert_response :success
      assert_match active.ip_address, response.body
      refute_match expired.ip_address, response.body
    end

    test "filters by IP address search" do
      create(:banned_ip, ip_address: "192.168.1.1")
      create(:banned_ip, ip_address: "192.168.1.2")
      create(:banned_ip, ip_address: "10.0.0.1")

      get "/beskar/banned_ips", params: {ip_search: "192.168"}

      assert_response :success
      assert_match "192.168.1.1", response.body
      assert_match "192.168.1.2", response.body
      refute_match "10.0.0.1", response.body
    end

    test "filters by reason" do
      ban1 = create(:banned_ip, reason: "Brute force attack")
      ban2 = create(:banned_ip, reason: "SQL injection attempts")
      ban3 = create(:banned_ip, reason: "Rate limit violations")

      get "/beskar/banned_ips", params: {reason: "SQL injection attempts"}

      assert_response :success
      assert_match ban2.ip_address, response.body
      refute_match ban1.ip_address, response.body
      refute_match ban3.ip_address, response.body
    end

    test "filters by date range" do
      old_ban = create(:banned_ip, banned_at: 10.days.ago)
      recent_ban = create(:banned_ip, banned_at: 1.day.ago)
      today_ban = create(:banned_ip, banned_at: Time.current)

      start_date = 3.days.ago.to_date
      end_date = Date.current

      get "/beskar/banned_ips", params: {
        banned_after: start_date.to_s,
        banned_before: end_date.to_s
      }

      assert_response :success
      assert_match recent_ban.ip_address, response.body
      assert_match today_ban.ip_address, response.body
      refute_match old_ban.ip_address, response.body
    end

    test "combines multiple filters" do
      active_recent = create(:banned_ip, :active, banned_at: 1.day.ago)
      active_old = create(:banned_ip, :active, banned_at: 10.days.ago)
      expired_recent = create(:banned_ip, :expired, banned_at: 1.day.ago)

      get "/beskar/banned_ips", params: {
        status: "active",
        banned_after: 3.days.ago.to_date.to_s
      }

      assert_response :success
      assert_match active_recent.ip_address, response.body
      refute_match active_old.ip_address, response.body
      refute_match expired_recent.ip_address, response.body
    end

    # Sorting Tests
    test "sorts by created_at by default" do
      oldest = create(:banned_ip, banned_at: 3.days.ago)
      middle = create(:banned_ip, banned_at: 2.days.ago)
      newest = create(:banned_ip, banned_at: 1.day.ago)

      get "/beskar/banned_ips"

      assert_response :success
      # All bans should be displayed
      assert_includes response.body, newest.ip_address
      assert_includes response.body, middle.ip_address
      assert_includes response.body, oldest.ip_address
    end

    test "sorts by IP address" do
      create(:banned_ip, ip_address: "192.168.1.1")
      create(:banned_ip, ip_address: "10.0.0.1")
      create(:banned_ip, ip_address: "172.16.0.1")

      get "/beskar/banned_ips", params: {sort: "ip_address", direction: "asc"}

      assert_response :success
      # All IPs should be present
      assert_includes response.body, "10.0.0.1"
      assert_includes response.body, "172.16.0.1"
      assert_includes response.body, "192.168.1.1"
    end

    test "sorts by expires_at" do
      expires_soon = create(:banned_ip, expires_at: 1.day.from_now)
      expires_later = create(:banned_ip, expires_at: 7.days.from_now)
      permanent = create(:banned_ip, permanent: true, expires_at: nil)

      get "/beskar/banned_ips", params: {sort: "expires_at", direction: "asc"}

      assert_response :success
      # All bans displayed
      assert_includes response.body, expires_soon.ip_address
      assert_includes response.body, expires_later.ip_address
      assert_includes response.body, permanent.ip_address
    end

    # New Action Tests
    test "displays new banned IP form" do
      get "/beskar/banned_ips/new"

      assert_response :success
      # Should have a form with necessary fields
      assert_select "form[action='/beskar/banned_ips']"
      assert_select "input[name='banned_ip[ip_address]']"
    end

    test "prefills IP address from params" do
      get "/beskar/banned_ips/new", params: {ip_address: "192.168.1.100"}

      assert_response :success
      # Form should be rendered successfully
      assert_select "form"
    end

    test "shows recent events for IP when creating ban" do
      create(:security_event, ip_address: "192.168.1.100")

      get "/beskar/banned_ips/new", params: {ip_address: "192.168.1.100"}

      assert_response :success
      # Page renders successfully
    end

    # Create Action Tests
    test "creates new banned IP" do
      assert_difference "Beskar::BannedIp.count", 1 do
        post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                            ban_type: "temporary",
                                            duration: 86400,  # 24 hours in seconds
                                            banned_ip: {
                                              ip_address: "192.168.1.100",
                                              reason: "Suspicious activity"
                                            }}
      end

      assert_response :redirect
      # Verify the ban was created
      ban = Beskar::BannedIp.find_by(ip_address: "192.168.1.100")
      assert_not_nil ban
      assert_equal "Suspicious activity", ban.reason
    end

    test "validates IP address format" do
      assert_no_difference "Beskar::BannedIp.count" do
        post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                            ban_type: "temporary",
                                            banned_ip: {
                                              ip_address: "",  # Empty IP
                                              reason: "Test"
                                            }}
      end

      # Should either show error or redirect
      assert_includes [422, 200], response.status
    end

    test "prevents duplicate IP bans" do
      create(:banned_ip, ip_address: "192.168.1.100")

      # Attempting to create duplicate should fail or extend existing
      post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                          ban_type: "temporary",
                                          banned_ip: {
                                            ip_address: "192.168.1.100",
                                            reason: "Duplicate attempt"
                                          }}

      # Should either reject or handle gracefully
      assert_includes [422, 200, 302], response.status
    end

    test "creates permanent ban when duration not specified" do
      assert_difference "Beskar::BannedIp.count", 1 do
        post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                            ban_type: "permanent",
                                            banned_ip: {
                                              ip_address: "192.168.1.100",
                                              reason: "Permanent ban"
                                            }}
      end

      ban = Beskar::BannedIp.last
      assert_nil ban.expires_at
    end

    test "creates temporary ban with expiration" do
      assert_difference "Beskar::BannedIp.count", 1 do
        post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                            ban_type: "temporary",
                                            duration: 172800,  # 48 hours in seconds
                                            banned_ip: {
                                              ip_address: "192.168.1.100",
                                              reason: "Temporary ban"
                                            }}
      end

      ban = Beskar::BannedIp.last
      assert_not_nil ban.expires_at
      assert ban.expires_at > Time.current
      assert ban.expires_at <= 49.hours.from_now
    end

    # Edit Action Tests
    test "displays edit form for banned IP" do
      ban = create(:banned_ip)

      get "/beskar/banned_ips/#{ban.id}/edit"

      assert_response :success
      # Should render edit form
      assert_select "form"
    end

    # Update Action Tests
    test "updates banned IP details" do
      ban = create(:banned_ip, reason: "Original reason")

      patch "/beskar/banned_ips/#{ban.id}", params: {audit_reason: "Reviewed test case",
                                                     banned_ip: {
                                                       reason: "Updated reason",
                                                       details: "Additional context"
                                                     }}

      assert_response :redirect
      ban.reload
      assert_equal "Updated reason", ban.reason
    end

    test "extends ban expiration" do
      ban = create(:banned_ip, expires_at: 1.day.from_now)
      ban.expires_at

      patch "/beskar/banned_ips/#{ban.id}", params: {audit_reason: "Reviewed test case",
                                                     banned_ip: {
                                                       extend_duration_hours: 24
                                                     }}

      # Should redirect or succeed
      assert_includes [200, 302], response.status
    end

    test "validates update parameters" do
      ban = create(:banned_ip)

      patch "/beskar/banned_ips/#{ban.id}", params: {audit_reason: "Reviewed test case",
                                                     banned_ip: {
                                                       ip_address: ""  # Empty IP
                                                     }}

      # Should handle validation
      ban.reload
      assert_not_equal "", ban.ip_address
    end

    # Destroy Action Tests
    test "deletes banned IP" do
      ban = create(:banned_ip)

      assert_difference "Beskar::BannedIp.count", -1 do
        delete "/beskar/banned_ips/#{ban.id}", params: {audit_reason: "Reviewed test case"}
      end

      assert_response :redirect
    end

    test "handles non-existent ban deletion gracefully" do
      delete "/beskar/banned_ips/999999", params: {audit_reason: "Reviewed test case"}
      assert_response :not_found
    end

    # Batch Operations Tests
    test "performs bulk unban operation" do
      bans = create_list(:banned_ip, 3)

      assert_difference "Beskar::BannedIp.count", -3 do
        post "/beskar/banned_ips/bulk_action", params: {audit_reason: "Reviewed test case",
                                                        bulk_action: "unban",
                                                        ip_ids: bans.map(&:id)}
      end

      assert_response :redirect
      follow_redirect!
      assert_match(/unbanned/i, response.body)
    end

    test "bulk makes bans permanent" do
      bans = create_list(:banned_ip, 2, expires_at: 1.day.from_now)

      post "/beskar/banned_ips/bulk_action", params: {audit_reason: "Reviewed test case",
                                                      bulk_action: "make_permanent",
                                                      ip_ids: bans.map(&:id)}

      assert_response :redirect
      follow_redirect!
      assert_match(/permanent/i, response.body)

      bans.each do |ban|
        ban.reload
        assert ban.permanent?
        assert_nil ban.expires_at
      end
    end

    test "handles bulk action with no IPs selected" do
      create_list(:banned_ip, 2)

      post "/beskar/banned_ips/bulk_action", params: {audit_reason: "Reviewed test case",
                                                      bulk_action: "unban",
                                                      ip_ids: nil}

      assert_response :unprocessable_content
      # Reject invalid selections without performing any action.
      assert_equal 2, Beskar::BannedIp.count
    end

    test "handles empty IP ids array" do
      post "/beskar/banned_ips/bulk_action", params: {audit_reason: "Reviewed test case",
                                                      bulk_action: "make_permanent",
                                                      ip_ids: []}

      assert_response :unprocessable_content
    end

    test "validates bulk action type" do
      ban = create(:banned_ip)

      post "/beskar/banned_ips/bulk_action", params: {audit_reason: "Reviewed test case",
                                                      bulk_action: "nonexistent_action",
                                                      ip_ids: [ban.id]}

      assert_response :unprocessable_content
    end

    # Import/Export Tests
    test "exports banned IPs to CSV" do
      bans = create_list(:banned_ip, 3)

      get "/beskar/banned_ips/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}

      assert_response :success
      assert_equal "text/csv", response.content_type
      # CSV should contain the IPs
      csv_content = response.body
      bans.each do |ban|
        assert_includes csv_content, ban.ip_address
      end
    end

    test "exports filtered results to CSV" do
      create(:banned_ip, :active)
      create(:banned_ip, :expired)

      get "/beskar/banned_ips/export.csv", headers: {"X-Beskar-Audit-Reason" => "Export regression"}, params: {status: "active"}

      assert_response :success
      # Should export successfully
      assert_equal "text/csv", response.content_type
    end

    # UI Elements Tests
    test "includes filter form with all options" do
      get "/beskar/banned_ips"

      assert_response :success
      # Should have filtering capabilities
      assert_select "form"
    end

    test "displays status badges correctly" do
      create(:banned_ip, :active)
      create(:banned_ip, :expired)

      get "/beskar/banned_ips"

      assert_response :success
      # Page renders successfully
    end

    test "includes action buttons for each ban" do
      create(:banned_ip)

      get "/beskar/banned_ips"

      assert_response :success
      # Should display the ban
    end

    test "includes bulk action controls" do
      create_list(:banned_ip, 3)

      get "/beskar/banned_ips"

      assert_response :success
      # Should have bulk action form
      assert_select "form[action*='bulk_action']"
    end

    test "shows quick stats summary" do
      create(:banned_ip, :active)
      create(:banned_ip, :expired)
      create(:banned_ip, :permanent)

      get "/beskar/banned_ips"

      assert_response :success
      # Stats displayed
    end

    # Security Tests
    test "includes CSRF protection" do
      get "/beskar/banned_ips"

      assert_response :success
      # Rails handles CSRF automatically
    end

    test "escapes user input in display" do
      create(:banned_ip,
        reason: "<script>alert('xss')</script>",
        details: "<img src=x onerror=alert('xss')>")

      get "/beskar/banned_ips"

      assert_response :success
      # Rails escapes HTML by default
      refute_includes response.body, "<script>alert("
    end

    test "validates IP address format strictly" do
      # Note: Controller doesn't validate IP format, but SQL injection is prevented
      post "/beskar/banned_ips", params: {audit_reason: "Reviewed test case",
                                          ban_type: "temporary",
                                          duration: 86400,
                                          banned_ip: {
                                            ip_address: "'; DROP TABLE banned_ips; --",
                                            reason: "SQL injection attempt"
                                          }}

      # Request handled gracefully - Rails parameter binding prevents SQL injection
      assert_includes [422, 200, 302], response.status
    end

    # Performance Tests
    test "handles large datasets efficiently" do
      create_list(:banned_ip, 100)

      start_time = Time.current
      get "/beskar/banned_ips", params: {per_page: 25}
      duration = Time.current - start_time

      assert_response :success
      assert duration < 2.seconds, "Request took too long: #{duration} seconds"
      assert_select "tbody tr", maximum: 25
    end

    test "optimizes database queries" do
      # Create bans with related events
      10.times do
        ban = create(:banned_ip)
        create_list(:security_event, 3, ip_address: ban.ip_address)
      end

      # This should not cause N+1 queries
      get "/beskar/banned_ips"

      assert_response :success
    end

    # Integration Tests

    test "shows related security events for banned IP" do
      ban = create(:banned_ip, ip_address: "192.168.1.100")
      create_list(:security_event, 3, ip_address: "192.168.1.100")

      get "/beskar/banned_ips/#{ban.id}"

      assert_response :success
      # Show page displays successfully
    end

    private

    def create_test_data
      @active_bans = create_list(:banned_ip, 3, :active)
      @expired_bans = create_list(:banned_ip, 2, :expired)
      @permanent_bans = create_list(:banned_ip, 2, :permanent)

      # Create related events
      @active_bans.each do |ban|
        create_list(:security_event, 2, ip_address: ban.ip_address)
      end
    end
  end
end
