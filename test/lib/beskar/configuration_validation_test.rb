require "test_helper"
require "open3"

class ConfigurationValidationTest < ActiveSupport::TestCase
  setup do
    @config = Beskar::Configuration.new
  end

  test "defaults validate without consulting the database or cache" do
    ActiveRecord::Base.expects(:connection).never
    Rails.cache.expects(:read).never
    Rails.cache.expects(:write).never
    assert_same @config, @config.validate!
    refute @config.auto_analyze_patterns?
  end

  test "section assignment restores nested defaults and copies caller-owned hashes" do
    input = {ip_attempts: {limit: 23}}
    @config.rate_limiting = input
    assert_equal 23, @config.rate_limiting[:ip_attempts][:limit]
    assert_equal 1.hour, @config.rate_limiting[:ip_attempts][:period]
    assert_equal 5, @config.rate_limiting[:account_attempts][:limit]
    input[:ip_attempts][:limit] = 0
    assert_equal 23, @config.rate_limiting[:ip_attempts][:limit]
    @config.waf = {decay_rates: {low: 12}}
    assert_equal 360, @config.waf[:decay_rates][:critical]
    assert_equal 12, @config.waf[:decay_rates][:low]
    assert @config.validate!
  end

  test "reassignment resets previous customizations while nested edits retain them" do
    @config.waf[:score_threshold] = 777
    @config.waf = {enabled: true}
    assert_equal 150, @config.waf[:score_threshold]
    @config.waf[:score_threshold] = 321
    @config.waf[:enabled] = false
    assert_equal 321, @config.waf[:score_threshold]
  end

  test "invalid configuration cannot publish partial changes or leak supplied values" do
    original = Beskar.configuration
    error = assert_raises(Beskar::Configuration::Error) do
      Beskar.configure do |config|
        config.monitor_only = true
        config.rate_limiting[:ip_attempts][:limit] = "SECRET_INVALID_LIMIT"
      end
    end
    assert_same original, Beskar.configuration
    refute Beskar.configuration.monitor_only?
    assert_includes error.message, "rate_limiting.ip_attempts.limit"
    refute_includes error.message, "SECRET_"
  end

  test "exceptions in a configure block leave the active object and nested values unchanged" do
    original = Beskar.configuration
    assert_raises(RuntimeError) do
      Beskar.configure do |config|
        config.waf[:decay_rates][:critical] = 1
        raise "configuration aborted"
      end
    end
    assert_same original, Beskar.configuration
    assert_equal 360, original.waf[:decay_rates][:critical]
  end

  test "retained block references cannot mutate a published configuration" do
    retained = nil
    Beskar.configure do |config|
      retained = config
      config.waf[:decay_rates][:low] = 7
      config.ip_whitelist = [+"198.51.100.1"]
    end
    retained.waf[:decay_rates][:low] = 0
    retained.ip_whitelist.first.replace("invalid")
    assert_equal 7, Beskar.configuration.waf[:decay_rates][:low]
    assert_equal ["198.51.100.1"], Beskar.configuration.ip_whitelist
    assert Beskar.configuration.validate!
  end

  test "numeric controls reject zero negative non-finite and wrong-type settings" do
    paths = [[:rate_limiting, :ip_attempts, :limit], [:rate_limiting, :account_attempts, :period],
      [:rate_limiting, :global_attempts, :limit], [:waf, :score_threshold], [:waf, :violation_window],
      [:waf, :permanent_block_after], [:waf, :max_violations_tracked], [:waf, :decay_rates, :critical],
      [:risk_based_locking, :auto_unlock_time], [:geolocation, :cache_ttl],
      [:emergency_password_reset, :total_locks_threshold]]
    paths.each do |path|
      [0, -1, Float::NAN, Float::INFINITY, "10", false].each do |value|
        config = Beskar::Configuration.new
        section = config.public_send(path.first)
        path[1...-1].each { |key| section = section.fetch(key) }
        section[path.last] = value
        assert_raises(Beskar::Configuration::Error, path.join(".")) { config.validate! }
      end
    end
  end

  test "counts require integers and optional time controls accept nil" do
    @config.rate_limiting[:ip_attempts][:limit] = 1.5
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.rate_limiting[:ip_attempts][:limit] = 1
    @config.risk_based_locking[:auto_unlock_time] = nil
    @config.waf[:permanent_block_after] = nil
    @config.risk_based_locking[:risk_threshold] = 0
    assert @config.validate!
    @config.risk_based_locking[:risk_threshold] = 101
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
  end

  test "unknown string obsolete and missing keys are rejected" do
    [{block_threshold: 2}, {monitor_only: true}, {"enabled" => true}, {SECRET_UNKNOWN_KEY: "SECRET_VALUE"}].each do |settings|
      @config.waf = settings
      error = assert_raises(Beskar::Configuration::Error) { @config.validate! }
      refute_includes error.message, "SECRET"
    end
    @config.waf = {}
    @config.waf.delete(:decay_rates)
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    assert_raises(Beskar::Configuration::Error) { @config.rate_limiting = nil }
  end

  test "security switches and authorization callbacks have explicit types" do
    @config.monitor_only = "false"
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.monitor_only = false
    @config.authenticate_admin = true
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.authenticate_admin = ->(_) { false }
    @config.audit_actor = true
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.audit_actor = ->(_) { "admin:123" }
    @config.waf[:enabled] = "false"
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
  end

  test "whitelist errors name entry positions without logging their contents" do
    @config.ip_whitelist = ["SECRET_BAD_IP"]
    error = assert_raises(Beskar::Configuration::Error) { @config.validate! }
    assert_includes error.message, "ip_whitelist[0]"
    refute_includes error.message, "SECRET"
    @config.ip_whitelist = ["198.51.100.0/24", "2001:db8::/32"]
    assert @config.validate!
  end

  test "WAF exclusions and durations are validated" do
    @config.waf[:request_exclusions] = [{path: %r{\A/reports/}, methods: [:get], categories: [:unknown_format]}]
    assert @config.validate!
    [{path: "/reports"}, {path: /reports/, methods: ["SECRET_METHOD"]},
      {path: /reports/, categories: [:misspelled]}, {path: /reports/, typo: true}].each do |rule|
      @config.waf[:request_exclusions] = [rule]
      error = assert_raises(Beskar::Configuration::Error) { @config.validate! }
      refute_includes error.message, "SECRET"
    end
    @config.waf = {block_durations: []}
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.waf = {block_durations: [1.hour, nil]}
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.waf = {record_not_found_exclusions: ["/reports"]}
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
  end

  test "unsupported capabilities and unreadable MaxMind paths fail explicitly" do
    @config.risk_based_locking[:lock_strategy] = :custom
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.risk_based_locking[:lock_strategy] = :none
    assert @config.validate!
    @config.geolocation[:provider] = :ip2location
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.geolocation = {provider: :maxmind, maxmind_city_db_path: "SECRET_MISSING_DATABASE"}
    error = assert_raises(Beskar::Configuration::Error) { @config.validate! }
    refute_includes error.message, "SECRET"
  end

  test "active background analysis requires a real job and names may be deferred until boot finishes" do
    @config.security_tracking[:auto_analyze_patterns] = true
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.security_tracking[:analysis_job] = "MissingHostAnalysisJob"
    assert @config.validate!(resolve_jobs: false)
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.security_tracking[:analysis_job] = String
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.security_tracking[:analysis_job] = "BeskarAnalysisTestJob"
    assert @config.validate!
    assert_equal BeskarAnalysisTestJob, @config.analysis_job_class
  end

  test "runtime configure resolves invalid job names before publication" do
    original = Beskar.configuration
    assert_raises(Beskar::Configuration::Error) do
      Beskar.configure { |config| config.security_tracking.merge!(auto_analyze_patterns: true, analysis_job: "MissingHostAnalysisJob") }
    end
    assert_same original, Beskar.configuration
  end

  test "application startup rejects invalid in-place settings after initializers" do
    output, status = boot_with("Beskar.configuration.waf[:score_threshold] = 0")
    refute status.success?
    assert_includes output, "waf.score_threshold must be finite and positive"
  end

  test "startup resolves a host job after the main autoloader is ready" do
    output, status = boot_with('Beskar.configuration.security_tracking.merge!(auto_analyze_patterns: true, analysis_job: "BeskarAnalysisTestJob")')
    assert status.success?, output
  end

  test "startup validation runs after host after_initialize callbacks" do
    output, status = boot_with("Rails.application.config.after_initialize { Beskar.configuration.monitor_only = 'SECRET_INVALID_BOOLEAN' }")
    refute status.success?
    assert_includes output, "monitor_only must be true or false"
    refute_includes output, "SECRET_INVALID_BOOLEAN"
  end

  test "notifications default off and enabled delivery requires explicit settings" do
    refute @config.notify_user_on_lock?
    refute @config.emergency_password_reset[:send_notification]
    refute @config.emergency_password_reset[:notify_security_team]
    @config.risk_based_locking[:notify_user] = true
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.notifications[:from] = "security@example.com"
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.notifications[:recovery_url] = "https://example.com/recovery"
    assert @config.validate!
    @config.emergency_password_reset[:notify_security_team] = true
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.notifications[:security_team_recipients] = ["team@example.com"]
    assert @config.validate!
  end

  test "notification mailboxes reject lists injection and bad types without exposing values" do
    ["SECRET_INVALID", "a@example.com,SECRET@example.com", "a@example.com\r\nBcc:SECRET@example.com", false, 123].each do |value|
      @config.notifications[:from] = value
      error = assert_raises(Beskar::Configuration::Error) { @config.validate! }
      refute_includes error.message, "SECRET"
    end
    @config.notifications[:from] = nil
    @config.notifications[:security_team_recipients] = ["bad"]
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
    @config.notifications[:security_team_recipients] = Array.new(21, "team@example.com")
    assert_raises(Beskar::Configuration::Error) { @config.validate! }
  end

  test "recovery links must be explicit HTTPS entry pages without bearer data" do
    ["http://example.com/recovery", "/recovery", "//example.com/recovery", "javascript:SECRET", "https://user:SECRET@example.com",
      "https://example.com/reset?token=SECRET", "https://example.com/reset#SECRET", "https://example.com/\r\nSECRET", 123].each do |value|
      @config.notifications[:recovery_url] = value
      error = assert_raises(Beskar::Configuration::Error) { @config.validate! }
      refute_includes error.message, "SECRET"
    end
  end

  private

  def boot_with(configuration)
    root = File.expand_path("../../..", __dir__)
    script = <<~RUBY
      require "./test/dummy/config/application"
      # Model configuration loaded at the end of config/initializers, before
      # Beskar registers its final validation callback.
      Rails.application.class.initializer("beskar.test_configuration", after: :load_config_initializers,
        before: "beskar.register_configuration_validation") do
        #{configuration}
      end
      Rails.application.initialize!
    RUBY
    stdout, stderr, status = Open3.capture3({"RAILS_ENV" => "test"}, RbConfig.ruby, "-e", script, chdir: root)
    [stdout + stderr, status]
  end
end
