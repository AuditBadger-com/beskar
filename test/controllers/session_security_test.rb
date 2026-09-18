require "test_helper"

class ProtectedApiTestController < ActionController::Base
  include Beskar::Controllers::SessionSecurity

  def index
    render plain: "protected data"
  end

  private

  def beskar_authenticated_user
    request.env["test.verified_user"]
  end

  def beskar_authenticated_generation
    request.env["test.verified_generation"]
  end
end

class ApiSessionSecurityTest < ActionController::TestCase
  tests ProtectedApiTestController

  setup do
    @routes = ActionDispatch::Routing::RouteSet.new
    @routes.draw { get "/", to: "protected_api_test#index" }
    @user = create(:user)
    @request.env["test.verified_user"] = @user
    @request.env["test.verified_generation"] = @user.beskar_session_token
  end

  test "a revoked token never reaches a protected action even after unlock" do
    get :index
    assert_response :success
    @user.revoke_beskar_sessions!
    get :index
    assert_response :unauthorized
    refute_includes response.body, "protected data"
  end

  test "missing identity and state outage fail closed" do
    @request.env.delete("test.verified_generation")
    get :index
    assert_response :unauthorized
    @request.env["test.verified_generation"] = @user.beskar_session_token
    Beskar::SecurityState.stubs(:read).raises(ActiveRecord::ConnectionNotEstablished)
    get :index
    assert_response :service_unavailable
  end
end
