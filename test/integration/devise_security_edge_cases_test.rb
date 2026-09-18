require "test_helper"
require_relative "../beskar_test_base"

class DeviseSecurityEdgeCasesTest < ActionDispatch::IntegrationTest
  include FactoryBot::Syntax::Methods

  def setup
    # Setup handled by parent class with worker isolation
    super

    # Create fresh test user for each test
    @user = create(:devise_user, email: "edge@example.com", password: "password123")
  end

  test "handles malformed login parameters gracefully" do
    # Test with completely malformed parameters
    # Devise handles malformed parameters gracefully without raising exceptions
    post "/devise_users/sign_in", params: {
      invalid: "structure"
    }, headers: {
      "X-Forwarded-For" => worker_ip(10)
    }

    # Should return 422 and render the login form (standard Devise behavior)
    assert_response :unprocessable_content
    assert_select "form" # Login form should be present
  end

  test "handles missing user parameters" do
    # Test with missing user hash
    post "/devise_users/sign_in", params: {}, headers: {
      "X-Forwarded-For" => worker_ip(11)
    }

    # Should not crash and should render the login form
    # Devise returns 422 for empty parameters but still shows the form
    assert_response :unprocessable_content
    assert_select "form" # Login form should be present
  end

  test "handles nil and empty email addresses without crashing" do
    test_cases = [
      {email: nil, password: "password123", description: "nil email"},
      {email: "", password: "password123", description: "empty email"},
      {email: "   ", password: "password123", description: "whitespace email"},
      {email: "valid@example.com", password: nil, description: "nil password"},
      {email: "valid@example.com", password: "", description: "empty password"}
    ]

    test_cases.each_with_index do |test_case, index|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: test_case[:email],
          password: test_case[:password]
        }
      }, headers: {
        "X-Forwarded-For" => worker_ip(20 + index),
        "User-Agent" => "EdgeCase/#{index}"
      }

      # Should handle gracefully without crashing
      # Devise returns 422 for invalid parameters but still shows the form
      assert_response :unprocessable_content, "Failed for #{test_case[:description]}"
    end
  end

  test "creates security events for valid email with invalid password" do
    test_email = "valid@example.com"
    ip = worker_ip(25)

    post "/devise_users/sign_in", params: {
      devise_user: {
        email: test_email,
        password: "wrongpassword"
      }
    }, headers: {
      "X-Forwarded-For" => ip,
      "User-Agent" => "EdgeCase/Test"
    }

    assert_response :unprocessable_content

    # Should record the failure while honoring the host email filter.
    event = Beskar::SecurityEvent.where(
      attempted_email: "[FILTERED]",
      ip_address: ip
    ).order(id: :desc).first

    assert_not_nil event, "Should create security event for valid email"
    assert_equal "login_failure", event.event_type
    assert_equal "[FILTERED]", event.attempted_email
  end

  test "handles extremely long email addresses" do
    # Test with very long email (potential DoS attack)
    long_email = "a" * 1000 + "@example.com"

    post "/devise_users/sign_in", params: {
      devise_user: {
        email: long_email,
        password: "password123"
      }
    }, headers: {
      "X-Forwarded-For" => worker_ip(30)
    }

    # Devise returns 422 for invalid parameters but still shows the form
    assert_response :unprocessable_content

    # Should still create security event but handle long email gracefully
    event = Beskar::SecurityEvent.where(ip_address: worker_ip(30)).order(id: :desc).first
    assert_not_nil event, "SecurityEvent should be created for long email attempt"
    # Even oversized email values honor the host's audit privacy policy.
    assert_not_nil event.attempted_email, "Email should be stored in attempted_email field"
    assert_equal "[FILTERED]", event.attempted_email, "Host email privacy policy applies to long addresses too"
  end

  test "handles special characters and encoding in parameters" do
    special_cases = [
      {email: "test+tag@example.com", description: "plus sign in email"},
      {email: "test@example.co.uk", description: "international domain"},
      {email: "用户@example.com", description: "unicode characters"},
      {email: "test@münchen.de", description: "internationalized domain"},
      {password: "pássword123", description: "password with accents"},
      {password: "密码123", description: "password with unicode"}
    ]

    special_cases.each_with_index do |test_case, index|
      params = {
        email: test_case[:email] || "default@example.com",
        password: test_case[:password] || "defaultpassword"
      }

      post "/devise_users/sign_in", params: {
        devise_user: params
      }, headers: {
        "X-Forwarded-For" => worker_ip(40 + index),
        "Content-Type" => "application/x-www-form-urlencoded; charset=UTF-8"
      }

      # Devise returns 422 for invalid parameters but still shows the form
      assert_response :unprocessable_content, "Failed for #{test_case[:description]}"

      # Should create security event that handles special characters
      event = Beskar::SecurityEvent.where(ip_address: worker_ip(40 + index)).order(id: :desc).first
      assert_not_nil event, "Should create security event for #{test_case[:description]}"
      assert_not_nil event.attempted_email, "Event should track attempted email"
      assert_not_nil event.metadata, "Event should have metadata"
    end
  end

  test "handles requests with missing or malformed headers" do
    header_cases = [
      {headers: {}, description: "no headers"},
      {headers: {"User-Agent" => ""}, description: "empty user agent"},
      {headers: {"X-Forwarded-For" => ""}, description: "empty forwarded IP"},
      {headers: {"User-Agent" => "\x00\x01\x02"}, description: "binary user agent"},
      {headers: {"X-Forwarded-For" => "not.an.ip.address"}, description: "invalid IP format"},
      {headers: {"X-Forwarded-For" => "999.999.999.999"}, description: "out of range IP"}
    ]

    header_cases.each_with_index do |test_case, index|
      previous_event_id = Beskar::SecurityEvent.maximum(:id) || 0
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "header#{index}@example.com",
          password: "wrongpassword"
        }
      }, headers: test_case[:headers]

      # Devise returns 422 for invalid parameters but still shows the form
      assert_response :unprocessable_content, "Failed for #{test_case[:description]}"

      # Should create security event with available data
      event = Beskar::SecurityEvent.where("id > ?", previous_event_id).order(id: :desc).first
      assert_not_nil event, "Should create security event for #{test_case[:description]}"
      assert_equal "login_failure", event.event_type
      # Should capture some IP address (might be localhost for missing headers)
      assert_not_nil event.ip_address, "Event should have an IP address"
    end
  end

  test "handles concurrent requests from same session" do
    # Simulate rapid concurrent requests from the same session
    session_id = "concurrent_session_#{Time.current.to_i}"
    test_ip = worker_ip(179)

    # Use a single thread to avoid Rails integration test threading issues
    # but simulate the concurrent behavior by making rapid sequential requests
    results = []

    # Make 5 rapid requests in sequence (simulating concurrent behavior)
    5.times do |i|
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "concurrent#{i}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "X-Forwarded-For" => test_ip,
        "Cookie" => "_session_id=#{session_id}",
        "User-Agent" => "ConcurrentTest/#{i}"
      }

      results << {thread: i, response_code: response.code, status: response.status}
    rescue => e
      results << {thread: i, error: e.message}
    end

    # All requests should complete without errors
    assert_equal 5, results.length
    results.each do |result|
      assert_nil result[:error], "Request #{result[:thread]} had error: #{result[:error]}" if result[:error]
    end

    # Should have created security events (may be fewer due to rate limiting)
    concurrent_events = Beskar::SecurityEvent.where(ip_address: test_ip)
    assert concurrent_events.count > 0, "Should have created security events for concurrent requests (found: #{concurrent_events.count})"
  end

  # test "handles cache failures gracefully" do
  #   # Mock rate limiter to return successful result even with cache failures
  #   Beskar::Services::RateLimiter.stubs(:check_authentication_attempt).returns({allowed: true})

  #   # Stub Rails cache to simulate failures
  #   Rails.cache.stubs(:read).raises(StandardError, "Cache failure")
  #   Rails.cache.stubs(:write).raises(StandardError, "Cache failure")
  #   Rails.cache.stubs(:delete).raises(StandardError, "Cache failure")

  #   # Even with cache failures, authentication should still proceed
  #   # (This tests graceful degradation, not successful login)
  #   post "/devise_users/sign_in", params: {
  #     devise_user: {
  #       email: @user.email,
  #       password: "wrongpassword"  # Use wrong password to test graceful failure handling
  #     }
  #   }, headers: {
  #     "X-Forwarded-For" => worker_ip(231)
  #   }

  #   # Should handle cache failures gracefully and return normal authentication failure
  #   assert_response :unprocessable_content
  #   assert_select "form" # Login form should still be present
  # end

  test "handles memory pressure and large payloads" do
    # Test with large payload that might cause memory issues
    large_data = "x" * 10000 # 10KB of data

    post "/devise_users/sign_in", params: {
      devise_user: {
        email: "large@example.com",
        password: "password123",
        extra_data: large_data # Large unused parameter
      }
    }, headers: {
      "X-Forwarded-For" => worker_ip(250)
    }

    # Devise returns 422 for invalid parameters but still shows the form
    assert_response :unprocessable_content
    # Should handle large payloads without crashing
  end

  test "handles requests with suspicious parameter names" do
    # Test parameter pollution and injection attempts
    suspicious_params = {
      :user => {
        email: "suspicious@example.com",
        password: "password123"
      },
      # Suspicious additional parameters that attackers might inject
      "user[admin]" => "true",
      "user[role]" => "admin",
      "__proto__" => "polluted",
      "constructor" => "injected",
      "password_confirmation" => "different_password"
    }

    post "/devise_users/sign_in", params: suspicious_params, headers: {
      "X-Forwarded-For" => worker_ip(24)
    }

    # Devise returns 422 for invalid parameters but still shows the form
    assert_response :unprocessable_content

    # The wrong credential scope did not run an authentication strategy. Do not
    # manufacture a failed login or account history from unrelated parameters.
    event = Beskar::SecurityEvent.where(ip_address: worker_ip(24)).order(id: :desc).first
    assert_nil event
  end

  test "handles logout without active session" do
    # Try to logout when not logged in
    delete "/devise_users/sign_out", headers: {
      "X-Forwarded-For" => worker_ip(204)
    }

    # Should handle gracefully
    assert_redirected_to root_path
  end

  test "handles session fixation attack attempts" do
    # Attempt session fixation by providing specific session ID
    fixed_session_id = "attacker_controlled_session_id"
    ip = worker_ip(215)

    # Test with invalid credentials to verify graceful handling of session fixation attempts
    post "/devise_users/sign_in", params: {
      devise_user: {
        email: @user.email,
        password: "wrongpassword"
      }
    }, headers: {
      "X-Forwarded-For" => ip,
      "Cookie" => "_session_id=#{fixed_session_id}"
    }

    # Should handle gracefully even with session fixation attempt
    assert_response :unprocessable_content
    assert_select "form" # Login form should be present

    # Should create security event for the failed attempt
    event = Beskar::SecurityEvent.where(ip_address: ip).order(id: :desc).first
    assert_equal "login_failure", event.event_type
  end

  test "handles requests with forged referrer headers" do
    suspicious_referrers = [
      "http://attacker.com/login",
      "javascript:alert('xss')",
      "data:text/html,<script>alert('xss')</script>",
      "file:///etc/passwd",
      "http://192.168.1.1/admin" # Internal network
    ]

    suspicious_referrers.each_with_index do |referrer, index|
      ip = worker_ip(210 + index)
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "referrer#{index}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "Referer" => referrer,
        "X-Forwarded-For" => ip
      }

      # Devise returns 422 for invalid parameters but still shows the form
      assert_response :unprocessable_content

      # Should create security event with elevated risk for suspicious referrer
      event = Beskar::SecurityEvent.where(ip_address: ip).order(id: :desc).first
      assert event.risk_score >= 10, "Suspicious referrer should have some risk score"
      if referrer.start_with?("http://", "https://")
        assert_equal referrer, event.metadata["referer"]
      else
        assert_nil event.metadata["referer"]
      end
    end
  end

  test "handles IP spoofing attempts" do
    # Test various X-Forwarded-For header manipulations
    # Note: Each attempt uses a unique IP to avoid cumulative WAF blocking
    # IP spoofing detection creates critical violations (95 points), and 2 violations
    # would exceed the default threshold (150) and cause blocking
    spoofing_attempts = [
      "127.0.0.1", # Localhost spoofing
      "10.0.0.1", # Private network
      "203.0.113.1, 203.0.113.2", # Multiple IPs
      "203.0.113.3, 203.0.113.4", # Reversed order
      "unknown, 203.0.113.5", # Unknown proxy
      "203.0.113.6:8080" # With port
    ]

    spoofing_attempts.each_with_index do |forwarded_for, index|
      previous_event_id = Beskar::SecurityEvent.maximum(:id) || 0
      # Use unique IP for each test to prevent cumulative WAF blocking
      post "/devise_users/sign_in", params: {
        devise_user: {
          email: "spoof#{index}@example.com",
          password: "wrongpassword"
        }
      }, headers: {
        "X-Forwarded-For" => forwarded_for,
        "X-Real-IP" => worker_ip(90 + index) # Unique IP per attempt
      }

      # Devise returns 422 for invalid parameters but still shows the form
      assert_response :unprocessable_content

      # Select evidence from this request, never an earlier loop iteration.
      event = Beskar::SecurityEvent.where("id > ?", previous_event_id).order(id: :desc).first
      # Should record IP address
      assert_not_nil event.ip_address
      assert event.risk_score >= 30
    end
  end
end
