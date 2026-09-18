require "test_helper"
require "action_cable/channel/test_case"

class ProtectedAuditTestChannel < ActionCable::Channel::Base
  prepend Beskar::Channels::SessionSecurity

  def subscribed
    stream_from "private-audit"
  end

  def change(_data)
    connection.beskar_authenticated_user.sessions.create!
    transmit({ok: true})
  end
end

class ChannelSessionSecurityTest < ActionCable::Channel::TestCase
  tests ProtectedAuditTestChannel

  setup do
    @user = create(:user)
    @request = ActionDispatch::TestRequest.create("REMOTE_ADDR" => "198.51.100.24")
    stub_connection(beskar_authenticated_user: @user, beskar_authenticated_generation: @user.beskar_session_token, request: @request)
    connection.stubs(:close)
  end

  test "all subscriptions and incoming actions validate the credential generation" do
    subscribe
    assert subscription.confirmed?
    assert_has_stream "private-audit"
    assert_difference "@user.sessions.count", 1 do
      perform :change
    end
    @user.revoke_beskar_sessions!
    connection.expects(:close).with(reason: "authentication_revoked", reconnect: false)
    assert_no_difference "@user.sessions.count" do
      perform :change
    end
    assert_no_streams
  end

  test "revoked outbound data is never transmitted" do
    subscribe
    @user.revoke_beskar_sessions!
    assert_no_difference "transmissions.size" do
      subscription.send(:transmit, {secret: "must not be sent"})
    end
    assert_no_streams
  end

  test "a connection's cached user cannot retain access after account deletion" do
    subscribe
    User.find(@user.id).destroy!
    assert @user.persisted?, "The connection deliberately retains a stale model"
    assert_no_difference "transmissions.size" do
      subscription.send(:transmit, {secret: "must not be sent"})
    end
    assert_no_streams
  end

  test "revocation before subscription rejects without starting streams" do
    @user.revoke_beskar_sessions!
    subscribe
    assert subscription.rejected?
    assert_no_streams
  end

  test "missing host readers and database outages reject subscriptions" do
    stub_connection
    subscribe
    assert subscription.rejected?
    stub_connection(beskar_authenticated_user: @user, beskar_authenticated_generation: @user.beskar_session_token, request: @request)
    Beskar::SecurityState.stubs(:read).raises(ActiveRecord::ConnectionNotEstablished)
    subscribe
    assert subscription.rejected?
  end
end
