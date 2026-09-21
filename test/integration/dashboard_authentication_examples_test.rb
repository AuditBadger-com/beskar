require "test_helper"
require "erb"

class DashboardAuthenticationExamplesTest < ActionDispatch::IntegrationTest
  setup do
    use_example(1)
    User.any_instance.stubs(:admin?).returns(true)
    User.any_instance.stubs(:beskar_permissions).returns(%w[read export])
  end

  test "Rails example resumes the signed session and identifies the export operator" do
    user = sign_in_native_user
    Current.reset

    get "/beskar/dashboard"
    assert_response :success

    get "/beskar/security_events/export", params: {format: :csv, audit_reason: "Review security events"}
    assert_response :success
    assert_equal "User:#{user.id}", Beskar::AdministrativeAction.order(:id).last.actor
  end

  test "Rails example denies missing and tampered cookies" do
    get "/beskar/dashboard"
    assert_response :not_found

    sign_in_native_user
    cookies[:session_id] = "#{cookies[:session_id]}tampered"
    get "/beskar/dashboard"
    assert_response :not_found
  end

  test "Rails example denies a deleted session" do
    user = sign_in_native_user
    user.sessions.destroy_all

    get "/beskar/dashboard"
    assert_response :not_found
  end

  test "Rails example honors a persistent account lock even if the session remains" do
    user = sign_in_native_user
    Beskar.configuration.monitor_only = false
    Beskar::Services::NativeAccountLock.require_manual_unlock!(user)
    assert user.sessions.exists?

    get "/beskar/dashboard"
    assert_response :not_found
  end

  test "Rails example requires both admin role and the requested permission" do
    sign_in_native_user
    User.any_instance.stubs(:admin?).returns(false)
    get "/beskar/dashboard"
    assert_response :not_found

    User.any_instance.stubs(:admin?).returns(true)
    User.any_instance.stubs(:beskar_permissions).returns([])
    get "/beskar/dashboard"
    assert_response :forbidden
  end

  test "Devise example resumes Warden authentication without a native session" do
    use_example(2, scope: :devise_user)
    DeviseUser.any_instance.stubs(:admin?).returns(true)
    DeviseUser.any_instance.stubs(:beskar_permissions).returns(%w[read export])
    user = create(:devise_user, password: "password123")

    get "/beskar/dashboard"
    assert_response :not_found
    post "/devise_users/sign_in", params: {devise_user: {email: user.email, password: "password123"}}
    assert_response :redirect

    Session.expects(:find_by).never
    get "/beskar/dashboard"
    assert_response :success
    get "/beskar/security_events/export", params: {format: :csv, audit_reason: "Review security events"}
    assert_response :success
    assert_equal "User:#{user.id}", Beskar::AdministrativeAction.order(:id).last.actor
  end

  private

  def sign_in_native_user
    user = create(:user)
    post "/session", params: {email_address: user.email_address, password: "password123"}
    assert_response :redirect
    user
  end

  # Execute the shipped example, adapting only the dummy app's Devise mapping.
  def use_example(number, scope: :user)
    path = File.expand_path("../../lib/generators/beskar/install/templates/initializer.rb.tt", __dir__)
    content = ERB.new(File.read(path)).result
    section = content.split("  # Option #{number}:", 2).last.split("  # Option #{number + 1}:", 2).first
    code = section.lines.drop_while { |line| !line.start_with?("  # config.authenticate_admin") }
      .map { |line| line.sub(/^  # ?/, "") }.join
    code = code.gsub("scope: :user", "scope: :#{scope}")
    config = Beskar.configuration
    eval(code, binding, path) # rubocop:disable Security/Eval
  end
end
