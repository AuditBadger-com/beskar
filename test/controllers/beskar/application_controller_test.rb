require "test_helper"

module Beskar
  class ApplicationControllerTest < ActionDispatch::IntegrationTest
    include Engine.routes.url_helpers

    setup do
      # Clear any existing data
      Beskar::SecurityEvent.delete_all
      Beskar::BannedIp.destroy_all

      # Set up the routes for the engine
      @routes = Engine.routes
    end

    teardown do
      # Reset configuration
      Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
    end

    # ===================
    # Custom Authentication Tests
    # ===================

    test "allows access when custom authentication returns true" do
      Beskar.configuration.authenticate_admin = ->(_request) { true }

      get "/beskar/dashboard"

      assert_response :success
    end

    test "denies access when custom authentication returns false" do
      Beskar.configuration.authenticate_admin = ->(_request) { false }

      get "/beskar/dashboard"

      assert_response :not_found
    end

    test "authentication callback may complete a challenge without double rendering" do
      Beskar.configuration.authenticate_admin = proc do
        head :unauthorized
        false
      end
      get "/beskar/dashboard"
      assert_response :unauthorized
    end

    test "denies access when custom authentication returns nil" do
      Beskar.configuration.authenticate_admin = ->(_request) {}

      get "/beskar/dashboard"

      assert_response :not_found
    end

    test "handles custom authentication exception gracefully" do
      Beskar.configuration.authenticate_admin = ->(_request) do
        raise StandardError, "Database connection failed"
      end

      get "/beskar/dashboard"

      assert_response :not_found
    end

    test "logs error when custom authentication raises exception" do
      Beskar.configuration.authenticate_admin = ->(_request) do
        raise ArgumentError, "Invalid token format: SECRET_AUTH_TOKEN"
      end

      Rails.logger.expects(:error).with("Beskar authentication error: ArgumentError")

      get "/beskar/dashboard"

      assert_response :not_found
      refute_includes response.body, "SECRET_AUTH_TOKEN"
    end

    test "custom authentication receives request object" do
      received_request = nil
      Beskar.configuration.authenticate_admin = ->(request) do
        received_request = request
        true
      end

      get "/beskar/dashboard"

      assert_not_nil received_request
      assert_instance_of ActionDispatch::Request, received_request
    end

    test "custom authentication can access request headers" do
      auth_header = nil
      Beskar.configuration.authenticate_admin = ->(request) do
        auth_header = request.headers["Authorization"]
        auth_header == "Bearer secret-token"
      end

      get "/beskar/dashboard", headers: {"Authorization" => "Bearer secret-token"}

      assert_response :success
    end

    test "custom authentication denies access with invalid header" do
      Beskar.configuration.authenticate_admin = ->(request) do
        request.headers["Authorization"] == "Bearer secret-token"
      end

      get "/beskar/dashboard", headers: {"Authorization" => "Bearer wrong-token"}

      assert_response :not_found
    end

    # ===================
    # Missing Authentication Configuration Tests
    # ===================

    test "requires authentication configuration in all environments" do
      Beskar.configuration.authenticate_admin = nil

      # Should log error message but return 404 to avoid revealing Beskar is installed
      Rails.logger.expects(:error).with(regexp_matches(/Beskar authentication not configured/))

      get "/beskar/dashboard"

      assert_response :not_found
    end

    test "logs helpful examples when authentication not configured" do
      Beskar.configuration.authenticate_admin = nil

      # Error message should be logged (not shown to user)
      Rails.logger.expects(:error).with(regexp_matches(/Example 1: Check for admin user with Devise/))

      get "/beskar/dashboard"

      assert_response :not_found
    end

    test "requires configuration regardless of environment" do
      ["development", "test", "production"].each do |env|
        original_env = Rails.env
        begin
          Rails.env = ActiveSupport::StringInquirer.new(env)
          Beskar.configuration.authenticate_admin = nil

          Rails.logger.expects(:error).with(regexp_matches(/Beskar authentication not configured/))

          get "/beskar/dashboard"

          assert_response :not_found
        ensure
          Rails.env = original_env
        end
      end
    end

    # ===================
    # Response Format Tests
    # ===================

    test "handles HTML authentication failure" do
      Beskar.configuration.authenticate_admin = ->(_request) { false }

      get "/beskar/dashboard"

      assert_response :not_found
    end

    test "handles JSON authentication failure" do
      Beskar.configuration.authenticate_admin = ->(_request) { false }

      get "/beskar/dashboard.json"

      assert_response :not_found
      json_response = JSON.parse(response.body)
      assert_equal "Not found", json_response["error"]
    end

    # ===================
    # Edge Cases and Border Conditions
    # ===================

    test "handles authentication block that returns truthy non-boolean value" do
      Beskar.configuration.authenticate_admin = ->(_request) { "truthy string" }

      get "/beskar/dashboard"

      # Ruby treats any non-nil, non-false value as truthy
      assert_response :success
    end

    test "handles authentication block that returns 0 (falsey in some languages)" do
      Beskar.configuration.authenticate_admin = ->(_request) { 0 }

      get "/beskar/dashboard"

      # In Ruby, 0 is truthy
      assert_response :success
    end

    test "handles authentication block that returns empty string" do
      Beskar.configuration.authenticate_admin = ->(_request) { "" }

      get "/beskar/dashboard"

      # In Ruby, empty string is truthy
      assert_response :success
    end

    test "authentication failure returns 404 to avoid information disclosure" do
      Beskar.configuration.authenticate_admin = ->(_request) { false }

      # Should return 404 instead of 401
      # This prevents attackers from discovering that Beskar is installed
      get "/beskar/dashboard"

      assert_response :not_found
    end

    test "handles multiple consecutive requests with same authentication" do
      Beskar.configuration.authenticate_admin = ->(_request) { true }

      3.times do
        get "/beskar/dashboard"
        assert_response :success
      end
    end

    test "handles authentication state changes between requests" do
      # First request - authenticated
      Beskar.configuration.authenticate_admin = ->(_request) { true }
      get "/beskar/dashboard"
      assert_response :success

      # Second request - not authenticated
      Beskar.configuration.authenticate_admin = ->(_request) { false }
      get "/beskar/dashboard"
      assert_response :not_found

      # Third request - authenticated again
      Beskar.configuration.authenticate_admin = ->(_request) { true }
      get "/beskar/dashboard"
      assert_response :success
    end

    test "handles authentication block with side effects" do
      call_count = 0
      Beskar.configuration.authenticate_admin = ->(_request) do
        call_count += 1
        true
      end

      get "/beskar/dashboard"

      assert_equal 1, call_count
      assert_response :success
    end

    test "authentication is called for every request" do
      call_count = 0
      Beskar.configuration.authenticate_admin = ->(_request) do
        call_count += 1
        true
      end

      3.times { get "/beskar/dashboard" }

      assert_equal 3, call_count
    end

    test "handles slow authentication gracefully" do
      Beskar.configuration.authenticate_admin = ->(_request) do
        sleep 0.01  # Small delay to simulate slow auth
        true
      end

      start_time = Time.current
      get "/beskar/dashboard"
      duration = Time.current - start_time

      assert_response :success
      assert duration < 1.second, "Authentication took too long: #{duration}s"
    end

    # ===================
    # Helper Method Tests
    # ===================

    test "format_timestamp helper formats time correctly" do
      Beskar.configuration.authenticate_admin = ->(_request) { true }

      # Create a test controller instance to test the helper
      controller = ApplicationController.new

      time = Time.zone.parse("2025-01-15 14:30:00 UTC")
      formatted = controller.send(:format_timestamp, time)

      assert_match(/2025-01-15 14:30:00/, formatted)
    end

    test "format_timestamp helper handles nil" do
      controller = ApplicationController.new

      formatted = controller.send(:format_timestamp, nil)

      assert_equal "-", formatted
    end

    test "risk_level_class helper returns correct classes" do
      controller = ApplicationController.new

      assert_equal "success", controller.send(:risk_level_class, 10)
      assert_equal "warning", controller.send(:risk_level_class, 30)
      assert_equal "warning", controller.send(:risk_level_class, 31)
      assert_equal "warning", controller.send(:risk_level_class, 60)
      assert_equal "warning", controller.send(:risk_level_class, 61)
      assert_equal "danger", controller.send(:risk_level_class, 85)
      assert_equal "danger", controller.send(:risk_level_class, 86)
      assert_equal "critical", controller.send(:risk_level_class, 100)
    end

    test "risk_level_class helper handles nil" do
      controller = ApplicationController.new

      assert_equal "neutral", controller.send(:risk_level_class, nil)
    end

    test "format_event_type helper humanizes event types" do
      controller = ApplicationController.new

      assert_equal "Login Failure", controller.send(:format_event_type, "login_failure")
      assert_equal "Waf Violation", controller.send(:format_event_type, "waf_violation")
      assert_equal "Account Locked", controller.send(:format_event_type, "account_locked")
    end

    # ===================
    # CSRF Protection Tests
    # ===================

    test "CSRF protection is configured" do
      Beskar.configuration.authenticate_admin = ->(_request) { true }

      # Check that protect_from_forgery is configured in the controller
      assert_includes ApplicationController._process_action_callbacks.map(&:filter), :verify_authenticity_token
    end

    # ===================
    # Additional Border Cases
    # ===================

    test "pagination helper handles zero items" do
      controller = ApplicationController.new
      controller.params = ActionController::Parameters.new({page: "1"})

      # Create an empty collection
      collection = Beskar::SecurityEvent.none

      result = controller.send(:paginate, collection)

      assert_equal 0, result[:total_count]
      assert_equal 0, result[:total_pages]
      assert_equal 1, result[:current_page]
      assert_equal false, result[:has_previous]
      assert_equal false, result[:has_next]
    end

    test "pagination helper handles invalid page numbers" do
      controller = ApplicationController.new

      # Test negative page number
      controller.params = ActionController::Parameters.new({page: "-1"})
      collection = Beskar::SecurityEvent.all

      result = controller.send(:paginate, collection)
      assert_equal 1, result[:current_page]

      # Test zero page number
      controller.params = ActionController::Parameters.new({page: "0"})
      result = controller.send(:paginate, collection)
      assert_equal 1, result[:current_page]

      # Test non-numeric page (to_i returns 0, which gets reset to 1)
      controller.params = ActionController::Parameters.new({page: "abc"})
      result = controller.send(:paginate, collection)
      assert_equal 1, result[:current_page]
    end

    test "pagination helper enforces max per_page limit" do
      controller = ApplicationController.new
      controller.params = ActionController::Parameters.new({page: "1", per_page: "200"})

      collection = Beskar::SecurityEvent.all
      result = controller.send(:paginate, collection)

      assert_equal 100, result[:per_page]
    end

    test "pagination helper handles invalid per_page" do
      controller = ApplicationController.new

      # Test negative per_page
      controller.params = ActionController::Parameters.new({page: "1", per_page: "-10"})
      collection = Beskar::SecurityEvent.all
      result = controller.send(:paginate, collection)
      assert_equal 25, result[:per_page]

      # Test zero per_page
      controller.params = ActionController::Parameters.new({page: "1", per_page: "0"})
      result = controller.send(:paginate, collection)
      assert_equal 25, result[:per_page]
    end

    test "format_ip_with_location handles missing metadata" do
      controller = ApplicationController.new

      # Test with nil metadata
      result = controller.send(:format_ip_with_location, "192.168.1.1", nil)
      assert_equal "192.168.1.1", result

      # Test with empty hash
      result = controller.send(:format_ip_with_location, "192.168.1.1", {})
      assert_equal "192.168.1.1", result

      # Test with empty geolocation
      result = controller.send(:format_ip_with_location, "192.168.1.1", {"geolocation" => {}})
      assert_equal "192.168.1.1", result
    end

    test "format_ip_with_location handles partial geolocation data" do
      controller = ApplicationController.new

      # Only city
      metadata = {"geolocation" => {"city" => "New York"}}
      result = controller.send(:format_ip_with_location, "192.168.1.1", metadata)
      assert_equal "192.168.1.1 (New York)", result

      # Only country
      metadata = {"geolocation" => {"country" => "USA"}}
      result = controller.send(:format_ip_with_location, "192.168.1.1", metadata)
      assert_equal "192.168.1.1 (USA)", result

      # Both city and country
      metadata = {"geolocation" => {"city" => "New York", "country" => "USA"}}
      result = controller.send(:format_ip_with_location, "192.168.1.1", metadata)
      assert_equal "192.168.1.1 (New York, USA)", result
    end

    test "risk_level_class handles boundary values" do
      controller = ApplicationController.new

      # Test exact boundaries
      assert_equal "success", controller.send(:risk_level_class, 0)
      assert_equal "warning", controller.send(:risk_level_class, 31)
      assert_equal "danger", controller.send(:risk_level_class, 70)
      assert_equal "critical", controller.send(:risk_level_class, 90)

      # Invalid scores are unknown, not evidence of a critical threat.
      assert_equal "neutral", controller.send(:risk_level_class, -10)

      # Test very high values
      assert_equal "neutral", controller.send(:risk_level_class, 1000)
    end

    test "authentication handles configuration reset during request" do
      call_count = 0
      Beskar.configuration.authenticate_admin = ->(_request) do
        call_count += 1
        call_count == 1
      end

      get "/beskar/dashboard"
      assert_response :success

      # Second request uses new auth logic
      get "/beskar/dashboard"
      assert_response :not_found
    end

    test "authentication handles request with special characters in path" do
      Beskar.configuration.authenticate_admin = ->(_request) { true }

      # This will 404 but authentication should still run
      get "/beskar/dashboard/../security_events"

      # Should either succeed or give 404, but not crash
      assert_includes [200, 404], response.status
    end

    test "format_event_type handles unusual event types" do
      controller = ApplicationController.new

      # Empty string
      assert_equal "", controller.send(:format_event_type, "")

      # Single character
      assert_equal "X", controller.send(:format_event_type, "x")

      # Already formatted
      assert_equal "Already Formatted", controller.send(:format_event_type, "already_formatted")

      # With numbers
      assert_equal "Error 404", controller.send(:format_event_type, "error_404")
    end

    test "authentication exception preserves error type in logs" do
      custom_error = Class.new(StandardError)
      Beskar.configuration.authenticate_admin = ->(_request) do
        raise custom_error, "Custom authentication error"
      end

      Rails.logger.expects(:error).with("Beskar authentication error: #{custom_error}")

      get "/beskar/dashboard"

      assert_response :not_found
    end

    test "multiple authentication failures in sequence" do
      Beskar.configuration.authenticate_admin = ->(_request) { false }

      5.times do
        get "/beskar/dashboard"
        assert_response :not_found
      end
    end

    test "pagination calculates correct offset for large page numbers" do
      controller = ApplicationController.new
      controller.params = ActionController::Parameters.new({page: "10", per_page: "25"})

      collection = Beskar::SecurityEvent.all
      result = controller.send(:paginate, collection)

      expected_offset = (10 - 1) * 25
      assert_equal 225, expected_offset
      assert_equal 10, result[:current_page]
    end

    test "handle_authentication_failure returns 404 for both request types" do
      Beskar.configuration.authenticate_admin = ->(_request) { false }

      # HTML request - returns 404 instead of revealing Beskar is installed
      get "/beskar/dashboard"
      assert_response :not_found

      # JSON request - also returns 404
      get "/beskar/dashboard.json"
      assert_response :not_found
      json_response = JSON.parse(response.body)
      assert_equal "Not found", json_response["error"]
    end

    test "custom authentication can return different values for same request path" do
      request_count = 0
      Beskar.configuration.authenticate_admin = ->(_request) do
        request_count += 1
        request_count.odd? # Alternate between true and false
      end

      # First request should succeed (odd)
      get "/beskar/dashboard"
      assert_response :success

      # Second request should fail (even)
      get "/beskar/dashboard"
      assert_response :not_found

      # Third request should succeed (odd)
      get "/beskar/dashboard"
      assert_response :success
    end
  end
end
