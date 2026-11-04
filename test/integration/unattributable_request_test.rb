require "test_helper"

# A request with no usable peer address, for example from an in-process Rack
# client, has nothing to ban or score. It must reach the host application.
class UnattributableRequestTest < ActionDispatch::IntegrationTest
  NO_ADDRESS = {"REMOTE_ADDR" => ""}.freeze

  test "the client address is nil when no usable address exists" do
    ["", "unknown", "unix:"].each do |value|
      assert_nil Beskar::Services::RequestContext.ip(ActionDispatch::TestRequest.create("REMOTE_ADDR" => value)), value.inspect
    end
  end

  test "the client address stays canonical when it is usable" do
    request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "203.0.113.5")

    assert_equal "203.0.113.5", Beskar::Services::RequestContext.ip(request)
  end

  test "an ordinary request reaches the application" do
    get "/devise_restricted", env: NO_ADDRESS

    assert_response :redirect
  end

  test "a scanner path records no violation and creates no state" do
    assert_no_difference ["Beskar::SecurityEvent.count", "Beskar::SecurityState.count", "Beskar::BannedIp.count"] do
      get "/.env", env: NO_ADDRESS
    end

    assert_response :not_found
  end

  test "an exception from the application is raised again and records no violation" do
    app = ->(_env) { raise ActiveRecord::RecordNotFound, "Couldn't find Post" }
    middleware = Beskar::Middleware::RequestAnalyzer.new(app)

    assert_no_difference ["Beskar::SecurityEvent.count", "Beskar::SecurityState.count"] do
      assert_raises(ActiveRecord::RecordNotFound) do
        middleware.call(Rack::MockRequest.env_for("/users/99999999.exe", "REMOTE_ADDR" => ""))
      end
    end
  end

  test "a login succeeds without an audit row" do
    user = create(:devise_user, email: "no-address@example.com", password: "password123")

    post "/devise_users/sign_in", params: {devise_user: {email: user.email, password: "password123"}}, env: NO_ADDRESS

    assert_response :redirect
    assert_equal 0, user.security_events.count
    get "/devise_restricted", env: NO_ADDRESS
    assert_response :success
  end
end
