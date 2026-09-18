# Configure Rails Environment
ENV["RAILS_ENV"] = "test"

require_relative "../test/dummy/config/environment"
ActiveRecord::Migrator.migrations_paths = [File.expand_path("dummy/db/migrate", __dir__), File.expand_path("../db/migrate", __dir__)]
require "rails/test_help"

# Configure FactoryBot
require "factory_bot_rails"

# Configure Mocha for mocking
require "mocha/minitest"

Rails.backtrace_cleaner.remove_silencers!

Minitest.backtrace_filter = Minitest::BacktraceFilter.new

# Simple test isolation helper
module TestHelper
  # Explicit test-only bootstrap; production configuration is sealed at boot.
  def self.configuration
    Beskar::Configuration.new.tap do |config|
      config.authorize_admin = ->(_request, _permission) { true }
      config.audit_actor = ->(_request) { "test:admin" }
    end
  end

  # Get unique IP address for each test method to prevent interference
  def self.unique_ip_for_test(test_name, suffix = 1)
    # Use test name hash for deterministic but unique IP
    hash = test_name.hash.abs % 200 + 10
    "192.168.#{hash}.#{suffix}"
  end
end

# Include FactoryBot methods in tests
class ActiveSupport::TestCase
  parallelize(workers: :number_of_processors)
  include FactoryBot::Syntax::Methods

  self.use_transactional_tests = true

  parallelize_setup do |worker|
    Rails.cache.clear
    # Reset Beskar configuration for each worker to prevent cross-test contamination
    Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
    Beskar.configuration.security_tracking[:enabled] = true
    Beskar.configuration.security_tracking[:track_successful_logins] = true
    Beskar.configuration.security_tracking[:track_failed_logins] = true
  end

  parallelize_teardown do |worker|
    Rails.cache.clear
    # Reset configuration after worker finishes
    Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
  end

  # Reset configuration and cache before each test to ensure isolation
  setup do
    # Only reset if not already done by a subclass (like BeskarTestBase)
    unless defined?(@beskar_config_reset)
      # Clear cache to prevent cross-test pollution from WAF violations and banned IPs
      Rails.cache.clear

      Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
      Beskar.configuration.security_tracking[:enabled] = true
      Beskar.configuration.security_tracking[:track_successful_logins] = true
      Beskar.configuration.security_tracking[:track_failed_logins] = true
      @beskar_config_reset = true
    end
  end
end

# Include FactoryBot in integration tests
class ActionDispatch::IntegrationTest
  include FactoryBot::Syntax::Methods

  # Per-worker setup for integration tests
  parallelize_setup do |worker|
    Rails.cache.clear
    # Reset Beskar configuration for each worker
    Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
    Beskar.configuration.security_tracking[:enabled] = true
    Beskar.configuration.security_tracking[:track_successful_logins] = true
    Beskar.configuration.security_tracking[:track_failed_logins] = true
  end

  parallelize_teardown do |worker|
    Rails.cache.clear
    # Reset configuration after worker finishes
    Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
  end

  setup do
    Rails.application.reload_routes_unless_loaded

    # Clear cache before each integration test to prevent cross-test pollution
    # This is critical for WAF violations and banned IPs that use cache
    Rails.cache.clear

    # Reset Beskar configuration before each integration test
    Beskar.instance_variable_set(:@configuration, TestHelper.configuration)
    Beskar.configuration.security_tracking[:enabled] = true
    Beskar.configuration.security_tracking[:track_successful_logins] = true
    Beskar.configuration.security_tracking[:track_failed_logins] = true
  end

  # Helper method to get unique IP addresses per test method
  def worker_ip(suffix = 1)
    test_name = "#{self.class.name}##{@NAME}"
    TestHelper.unique_ip_for_test(test_name, suffix)
  end
end

FactoryBot.definition_file_paths = [File.expand_path("factories", __dir__)]
