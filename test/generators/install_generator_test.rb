require "test_helper"
require "generators/beskar/install/install_generator"
require "fileutils"
require "open3"

class InstallGeneratorTest < Rails::Generators::TestCase
  # Disable parallelization for generator tests due to filesystem operations
  parallelize(workers: 1)

  tests Beskar::Generators::InstallGenerator
  destination File.expand_path("../../tmp/generator_test", __dir__)

  def setup
    super
    prepare_destination
  end

  def teardown
    super
    # Clean up after each test
    FileUtils.rm_rf(destination_root) if File.exist?(destination_root)
  end

  test "generator creates initializer file" do
    run_generator

    assert_file "config/initializers/beskar.rb" do |content|
      # Check that the file contains the main Beskar configuration block
      assert_match(/Beskar\.configure do \|config\|/, content)

      # Check for authentication configuration section
      assert_match(/DASHBOARD AUTHENTICATION/, content)
      assert_match(/config\.authenticate_admin/, content)
      assert_match(/config\.audit_actor/, content)
      assert_match(%r{docs/guides/audit-lifecycle\.md}, content)

      # Check for monitor_only mode configuration
      assert_match(/config\.monitor_only/, content)

      # Check for IP whitelist configuration
      assert_match(/config\.ip_whitelist/, content)

      # Check for WAF configuration with new score-based system
      assert_match(/WAF \(WEB APPLICATION FIREWALL\)/, content)
      assert_match(/config\.waf\[:enabled\] = true/, content)

      # Verify new score-based parameters are documented
      assert_match(/score_threshold/, content)
      assert_match(/violation_window/, content)
      assert_match(/permanent_block_after/, content)

      # Verify exponential decay configuration is present
      assert_match(/Exponential Decay Configuration/, content)
      assert_match(/decay_enabled/, content)
      assert_match(/decay_rates/, content)
      assert_match(/critical:.*360/, content)  # 6 hour half-life
      assert_match(/high:.*120/, content)      # 2 hour half-life
      assert_match(/medium:.*45/, content)     # 45 min half-life
      assert_match(/low:.*15/, content)        # 15 min half-life

      # Verify RecordNotFound exclusions are documented
      assert_match(/record_not_found_exclusions/, content)

      # Verify reference to the current WAF tuning guide
      assert_match(%r{docs/guides/audit-and-waf\.md}, content)
      assert_match(/STRICT/, content)
      assert_match(/BALANCED/, content)
      assert_match(/PERMISSIVE/, content)

      # Check for other configuration sections
      assert_match(/SECURITY TRACKING/, content)
      assert_match(/RATE LIMITING/, content)
      assert_match(/RISK-BASED ACCOUNT LOCKING/, content)
      assert_match(/GEOLOCATION/, content)
    end
  end

  test "generator defaults to monitor mode in every environment" do
    run_generator
    assert_file "config/initializers/beskar.rb", /config\.monitor_only = true/
  end

  test "generator does not reference obsolete block_threshold parameter" do
    run_generator

    assert_file "config/initializers/beskar.rb" do |content|
      # Should NOT contain the old block_threshold parameter
      refute_match(/block_threshold.*Number of violations/, content)
      refute_match(/config\.waf\[:block_threshold\] = 3/, content)
    end
  end

  test "generator includes proper default values in comments" do
    run_generator

    assert_file "config/initializers/beskar.rb" do |content|
      # Verify score threshold default
      assert_match(/score_threshold.*150/, content)

      # Verify violation window default
      assert_match(/violation_window.*6\.hours/, content)

      # Verify permanent block after default
      assert_match(/permanent_block_after.*500/, content)

      # Verify decay rates defaults
      assert_match(/critical:.*360/, content)
      assert_match(/high:.*120/, content)
      assert_match(/medium:.*45/, content)
      assert_match(/low:.*15/, content)
    end
  end

  test "generator mounts Beskar engine in routes" do
    # Create config directory and routes file before running generator
    config_dir = File.join(destination_root, "config")
    FileUtils.mkdir_p(config_dir)
    routes_file = File.join(config_dir, "routes.rb")
    File.write(routes_file, <<~RUBY)
      Rails.application.routes.draw do
        # Existing routes
      end
    RUBY

    run_generator

    assert File.exist?(routes_file), "Routes file should exist"
    content = File.read(routes_file)
    assert_match(/mount Beskar::Engine => '\/beskar'/, content)
  end

  test "generator does not duplicate route if already mounted" do
    # Create routes file with existing Beskar mount
    config_dir = File.join(destination_root, "config")
    FileUtils.mkdir_p(config_dir)
    routes_file = File.join(config_dir, "routes.rb")
    File.write(routes_file, <<~RUBY)
      Rails.application.routes.draw do
        mount Beskar::Engine => '/beskar'
        # Other routes
      end
    RUBY

    run_generator

    # Verify route appears only once
    assert File.exist?(routes_file), "Routes file should exist"
    content = File.read(routes_file)
    mount_count = content.scan("mount Beskar::Engine").count
    assert_equal 1, mount_count, "Route should only appear once"
  end

  test "generator displays installation instructions" do
    # Generator's show_readme method outputs instructions
    # Just verify the method exists and is called
    assert_respond_to generator, :show_readme
  end

  test "generator includes proper documentation references" do
    # Check that the generator file references documentation
    generator_file = File.read(File.expand_path("../../lib/generators/beskar/install/install_generator.rb", __dir__))

    assert_match(/README\.md/, generator_file)
    assert_match(/Beskar Installation Complete/, generator_file)
  end

  test "initializer file is properly formatted ruby" do
    run_generator

    assert_file "config/initializers/beskar.rb" do |content|
      # Should be valid Ruby (no syntax errors)
      assert_nothing_raised do
        # Just check if it parses without errors
        RubyVM::InstructionSequence.compile(content)
      end
    end
  end

  test "generator copies every migration into the destination and is idempotent" do
    source = File.expand_path("../../db/migrate", __dir__)
    migration_names = Dir.glob("#{source}/*.rb").map { |file| File.basename(file).sub(/^\d+_/, "") }
    run_generator
    migration_names.each do |name|
      files = Dir.glob(File.join(destination_root, "db/migrate/*_#{name}"))
      assert_equal 1, files.size, "Expected one copied #{name}"
      RubyVM::InstructionSequence.compile_file(files.first)
    end
    run_generator ["--skip"]
    assert_equal migration_names.size, Dir.glob(File.join(destination_root, "db/migrate/*.rb")).size
    assert_empty Dir.glob(File.join(destination_root, "*_db"))
  end

  test "copied migrations create security tables in a fresh database" do
    run_generator
    code = <<~RUBY
      ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ARGV.fetch(0))
      ActiveRecord::MigrationContext.new(ARGV.fetch(1)).migrate
      connection = ActiveRecord::Base.connection
      abort "missing state table" unless connection.table_exists?(:beskar_security_states)
      abort "missing events table" unless connection.table_exists?(:beskar_security_events)
      abort "missing bans table" unless connection.table_exists?(:beskar_banned_ips)
      abort "missing administrative history" unless connection.table_exists?(:beskar_administrative_actions)
      abort "missing operation index" unless connection.indexes(:beskar_administrative_actions).any? { |index| index.unique && index.columns == ["operation_id", "target_id"] }
      abort "missing lock version" unless connection.columns(:beskar_security_states).any? { |column| column.name == "lock_version" }
    RUBY
    output, error, status = Open3.capture3(RbConfig.ruby, "-rbundler/setup", "-ractive_record", "-e", code,
      File.join(destination_root, "fresh.sqlite3"), File.join(destination_root, "db/migrate"))
    assert status.success?, "Fresh migration failed: #{output}\n#{error}"
  end

  test "generator respects migrations already copied by the engine rake task" do
    run_generator
    files = Dir.glob(File.join(destination_root, "db/migrate/*.rb"))
    files.each { |file| File.rename(file, file.sub(/\.rb\z/, ".beskar.rb")) }
    run_generator ["--skip"]
    assert_equal files.size, Dir.glob(File.join(destination_root, "db/migrate/*.rb")).size
  end

  test "initializer contains all required configuration sections" do
    run_generator

    assert_file "config/initializers/beskar.rb" do |content|
      required_sections = [
        "DASHBOARD AUTHENTICATION",
        "MONITOR-ONLY MODE",
        "IP WHITELIST",
        "WAF (WEB APPLICATION FIREWALL)",
        "SECURITY TRACKING",
        "RATE LIMITING",
        "RISK-BASED ACCOUNT LOCKING",
        "GEOLOCATION",
        "AUTHENTICATION MODELS",
        "EMERGENCY PASSWORD RESET"
      ]

      required_sections.each do |section|
        assert_match(/#{Regexp.escape(section)}/, content,
          "Initializer should contain #{section} section")
      end
    end
  end

  private

  def prepare_destination
    FileUtils.rm_rf(destination_root)
    FileUtils.mkdir_p(destination_root)
  end
end
