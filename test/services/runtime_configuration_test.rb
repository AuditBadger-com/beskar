require "test_helper"

class RuntimeConfigurationTest < ActiveSupport::TestCase
  self.use_transactional_tests = false

  setup do
    @actor = "configuration-test:#{SecureRandom.hex(8)}"
    actor = @actor
    Beskar.configuration.authorize_configuration = ->(candidate) { candidate == actor }
    Beskar.configuration.seal!
  end

  teardown do
    Beskar::AdministrativeAction.where(actor: @actor).delete_all
  end

  test "sealed configuration rejects direct and nested mutation and wholesale replacement" do
    assert_raises(FrozenError) { Beskar.configuration.monitor_only = true }
    assert_raises(FrozenError) { Beskar.configuration.rate_limiting[:ip_attempts][:limit] = 1 }
    assert_raises(FrozenError) { Beskar.configuration.ip_whitelist << "198.51.100.1" }
    assert_raises(Beskar::Configuration::Error) { Beskar.configuration = Beskar::Configuration.new }
  end

  test "authorized runtime publication requires a complete history record" do
    assert_difference "Beskar::AdministrativeAction.count", 1 do
      reconfigure { |config| config.rate_limiting[:ip_attempts][:limit] = 42 }
    end
    entry = Beskar::AdministrativeAction.where(actor: @actor).last
    assert_equal "configuration_changed", entry.action
    assert_equal "Configuration", entry.target_type
    assert_equal 10, entry.before_state.dig("rate_limiting", "ip_attempts", "limit")
    assert_equal 42, entry.after_state.dig("rate_limiting", "ip_attempts", "limit")
    assert_equal 3600, entry.after_state.dig("rate_limiting", "ip_attempts", "period")
    assert_includes entry.after_state["changed_settings"], "rate_limiting"
    assert_equal 42, Beskar.configuration.rate_limiting[:ip_attempts][:limit]
    assert Beskar.configuration.frozen?
  end

  test "unauthorized invalid and unauditable changes cannot publish" do
    original = Beskar.configuration
    assert_raises(Beskar::Configuration::Error) { Beskar.configure { flunk "Unauthorized block ran" } }
    assert_raises(Beskar::Configuration::Error) { reconfigure { |config| config.rate_limiting[:ip_attempts][:limit] = -1 } }
    Beskar::AdministrativeAction.stubs(:create!).raises(ActiveRecord::ConnectionNotEstablished)
    assert_raises(ActiveRecord::ConnectionNotEstablished) { reconfigure { |config| config.monitor_only = true } }
    assert_same original, Beskar.configuration
    assert_equal 0, Beskar::AdministrativeAction.where(actor: @actor).count
  end

  test "runtime publication cannot escape an enclosing transaction rollback" do
    Beskar::AdministrativeAction.transaction do
      assert_raises(Beskar::Configuration::Error) { reconfigure { flunk "Transaction must be rejected first" } }
    end
  end

  private

  def reconfigure(&block)
    Beskar.configure(actor: @actor, reason: "Capacity review", request_id: SecureRandom.uuid, &block)
  end
end
