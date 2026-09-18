require "test_helper"

class AvailabilityIsolationTest < ActionDispatch::IntegrationTest
  test "a distributed campaign cannot exhaust a default global login budget" do
    user = create(:user, password: "password123")
    105.times do |index|
      request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.#{index + 1}")
      assert Beskar::Services::RateLimiter.check_authentication_attempt(request, :failure)[:allowed]
    end
    refute Beskar::SecurityState.where(key: "rate:enforce:global").exists?
    post "/session", params: {email_address: user.email_address, password: "password123"}, headers: {"REMOTE_ADDR" => "203.0.113.24"}
    assert_response :redirect
    assert_equal 1, user.sessions.count
  end

  test "authentication abuse behind a NAT does not block unrelated page requests or create an IP ban by default" do
    ip = "198.51.100.53"
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => ip)
    10.times { Beskar::Services::RateLimiter.check_authentication_attempt(request, :failure) }
    refute Beskar::Services::RateLimiter.check_ip_rate_limit(ip)[:allowed]
    6.times do
      get "/", headers: {"REMOTE_ADDR" => ip}
      assert_response :success
    end
    refute Beskar::BannedIp.banned?(ip)
  end

  test "ordinary traffic does not query or lock authentication quota rows" do
    Beskar::Services::RateLimiter.expects(:check_ip_rate_limit).never
    Beskar::SecurityState.expects(:mutate).never
    get "/"
    assert_response :success
  end

  test "an enforcement database outage fails closed without exposing internals" do
    Beskar::BannedIp.stubs(:banned?).raises(ActiveRecord::ConnectionNotEstablished, "private database address")
    get "/"
    assert_response :service_unavailable
    assert_equal "60", response.headers["Retry-After"]
    assert_includes response.headers["Cache-Control"], "no-store"
    refute_includes response.body, "private database address"
  end

  test "a host database exception is not mislabeled as a Beskar availability response" do
    middleware = Beskar::Middleware::RequestAnalyzer.new(->(_) { raise ActiveRecord::StatementInvalid, "host failure" })
    assert_raises(ActiveRecord::StatementInvalid) { middleware.call(Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "198.51.100.24")) }
  end
end
