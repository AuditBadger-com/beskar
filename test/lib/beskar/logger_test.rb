# frozen_string_literal: true

require "test_helper"
require "stringio"
require "logger"
require "mocha/minitest"

class Beskar::LoggerTest < ActiveSupport::TestCase
  setup do
    # Store original settings
    @original_logger = Beskar::Logger.logger
    @original_level = Beskar::Logger.level
    @original_aliases = Beskar::Logger.component_aliases.dup

    # Create a test logger with StringIO
    @log_output = StringIO.new
    @test_logger = ::Logger.new(@log_output)
    @test_logger.level = ::Logger::DEBUG
    Beskar::Logger.logger = @test_logger
    Beskar::Logger.level = :debug
  end

  teardown do
    # Restore original settings
    Beskar::Logger.logger = @original_logger
    Beskar::Logger.level = @original_level
    Beskar::Logger.component_aliases = @original_aliases
  end

  test "logs at all levels" do
    Beskar::Logger.debug("Debug message")
    Beskar::Logger.info("Info message")
    Beskar::Logger.warn("Warn message")
    Beskar::Logger.error("Error message")
    Beskar::Logger.fatal("Fatal message")

    output = @log_output.string
    assert_match(/\[Beskar\] Debug message/, output)
    assert_match(/\[Beskar\] Info message/, output)
    assert_match(/\[Beskar\] Warn message/, output)
    assert_match(/\[Beskar\] Error message/, output)
    assert_match(/\[Beskar\] Fatal message/, output)
  end

  test "includes component name when specified as symbol" do
    Beskar::Logger.info("Test message", component: :WAF)

    output = @log_output.string
    assert_match(/\[Beskar::WAF\] Test message/, output)
  end

  test "includes component name when specified as string" do
    Beskar::Logger.warn("Warning message", component: "RateLimiter")

    output = @log_output.string
    assert_match(/\[Beskar::RateLimiter\] Warning message/, output)
  end

  test "includes component name when specified as class" do
    Beskar::Logger.error("Error message", component: Beskar::Services::Waf)

    output = @log_output.string
    # Should use the alias for cleaner output
    assert_match(/\[Beskar::WAF\] Error message/, output)
  end

  test "respects log level settings" do
    Beskar::Logger.level = :warn

    Beskar::Logger.debug("Debug - should not appear")
    Beskar::Logger.info("Info - should not appear")
    Beskar::Logger.warn("Warn - should appear")
    Beskar::Logger.error("Error - should appear")

    output = @log_output.string
    refute_match(/Debug - should not appear/, output)
    refute_match(/Info - should not appear/, output)
    assert_match(/Warn - should appear/, output)
    assert_match(/Error - should appear/, output)
  end

  test "component aliases work correctly" do
    # Test default aliases
    Beskar::Logger.info("Message 1", component: "Beskar::Services::Waf")
    assert_match(/\[Beskar::WAF\] Message 1/, @log_output.string)

    # Test custom aliases
    Beskar::Logger.component_aliases = {
      "CustomComponent" => "Custom",
      "Beskar::LongComponentName" => "LCN"
    }

    Beskar::Logger.info("Message 2", component: "CustomComponent")
    Beskar::Logger.info("Message 3", component: "Beskar::LongComponentName")

    output = @log_output.string
    assert_match(/\[Beskar::Custom\] Message 2/, output)
    assert_match(/\[Beskar::LCN\] Message 3/, output)
  end

  test "handles nil component gracefully" do
    Beskar::Logger.info("Message with nil", component: nil)

    output = @log_output.string
    assert_match(/\[Beskar\] Message with nil/, output)
  end

  test "instance methods work when module is included" do
    test_class = Class.new do
      include Beskar::Logger

      def do_something
        log_info("Instance method logging")
        log_error("Instance error")
      end
    end

    # Mock the class name
    test_class.stubs(:name).returns("TestService")
    instance = test_class.new
    instance.do_something

    output = @log_output.string
    assert_match(/\[Beskar::TestService\] Instance method logging/, output)
    assert_match(/\[Beskar::TestService\] Instance error/, output)
  end

  test "class methods work when module is included" do
    test_class = Class.new do
      include Beskar::Logger

      def self.configure
        log_debug("Class method logging")
        log_warn("Class warning")
      end
    end

    # Mock the class name
    test_class.stubs(:name).returns("TestService")
    test_class.configure

    output = @log_output.string
    assert_match(/\[Beskar::TestService\] Class method logging/, output)
    assert_match(/\[Beskar::TestService\] Class warning/, output)
  end

  test "falls back to default logger when Rails.logger is not available" do
    # This test would need to mock Rails not being defined
    # For now, just test that logger can be set to nil and recovered
    Beskar::Logger.logger = nil

    # Should create a default logger
    assert_not_nil Beskar::Logger.logger

    # Should still be able to log
    Beskar::Logger.info("Test with default logger")
    # No assertion needed - just shouldn't raise
  end

  test "handles logging errors gracefully" do
    # Create a logger that raises errors
    bad_logger = Object.new
    def bad_logger.debug(*args)
      raise "Logging failed!"
    end

    def bad_logger.info(*args)
      raise "Logging failed!"
    end

    Beskar::Logger.logger = bad_logger

    # Capture stderr
    original_stderr = $stderr
    stderr_output = StringIO.new
    $stderr = stderr_output

    # Should not raise, but log to stderr
    Beskar::Logger.info("This will fail")

    stderr_content = stderr_output.string
    assert_match(/Logging unavailable \(RuntimeError\)/, stderr_content)
    refute_match(/This will fail/, stderr_content)
  ensure
    $stderr = original_stderr if defined?(original_stderr)
  end

  test "reset! restores defaults" do
    # Change settings
    custom_logger = ::Logger.new(StringIO.new)
    Beskar::Logger.logger = custom_logger
    Beskar::Logger.level = :fatal
    Beskar::Logger.component_aliases = {"Test" => "T"}

    # Reset
    Beskar::Logger.reset!

    # Check defaults are restored
    assert_not_equal custom_logger, Beskar::Logger.logger
    assert_equal :debug, Beskar::Logger.level
    assert_not_equal({"Test" => "T"}, Beskar::Logger.component_aliases)
    # Should have default aliases again
    assert_equal "WAF", Beskar::Logger.component_aliases["Beskar::Services::Waf"]
  end

  test "extracts last component from nested class names without alias" do
    Beskar::Logger.component_aliases = {} # Clear all aliases

    Beskar::Logger.info("Message", component: "Beskar::Some::Deep::Component")

    output = @log_output.string
    assert_match(/\[Beskar::Component\] Message/, output)
  end

  test "handles module as component" do
    test_module = Module.new
    test_module.stubs(:name).returns("TestModule")
    Beskar::Logger.info("Module message", component: test_module)

    output = @log_output.string
    assert_match(/\[Beskar::TestModule\] Module message/, output)
  end

  test "log method works directly" do
    Beskar::Logger.log(:info, "Direct log call", component: :Direct)

    output = @log_output.string
    assert_match(/\[Beskar::Direct\] Direct log call/, output)
  end

  test "should_log? respects log level" do
    Beskar::Logger.level = :warn

    # Use send to access private method
    assert_equal false, Beskar::Logger.send(:should_log?, :debug)
    assert_equal false, Beskar::Logger.send(:should_log?, :info)
    assert_equal true, Beskar::Logger.send(:should_log?, :warn)
    assert_equal true, Beskar::Logger.send(:should_log?, :error)
    assert_equal true, Beskar::Logger.send(:should_log?, :fatal)
  end

  test "handles empty component string" do
    Beskar::Logger.info("Message", component: "")

    output = @log_output.string
    assert_match(/\[Beskar\] Message/, output)
  end

  test "preserves component name if no alias exists" do
    Beskar::Logger.component_aliases = {} # Clear all aliases

    Beskar::Logger.info("Message", component: "UnknownComponent")

    output = @log_output.string
    assert_match(/\[Beskar::UnknownComponent\] Message/, output)
  end

  test "all instance logging methods are available" do
    test_class = Class.new do
      include Beskar::Logger

      def test_all_methods
        log_debug("Debug")
        log_info("Info")
        log_warn("Warn")
        log_error("Error")
        log_fatal("Fatal")
      end
    end

    instance = test_class.new

    # All methods should be available
    assert instance.respond_to?(:log_debug)
    assert instance.respond_to?(:log_info)
    assert instance.respond_to?(:log_warn)
    assert instance.respond_to?(:log_error)
    assert instance.respond_to?(:log_fatal)

    # And they should work
    instance.test_all_methods

    output = @log_output.string
    assert_match(/Debug/, output)
    assert_match(/Info/, output)
    assert_match(/Warn/, output)
    assert_match(/Error/, output)
    assert_match(/Fatal/, output)
  end

  test "component aliases handle variations of the same component" do
    # Test that various forms of the same component resolve correctly
    variations = [
      "Beskar::Services::Waf",
      "Services::Waf",
      "Beskar::Services::WAF",
      "Services::WAF"
    ]

    variations.each do |variant|
      @log_output.truncate(0) # Clear output
      Beskar::Logger.info("Test", component: variant)
      assert_match(/\[Beskar::WAF\] Test/, @log_output.string,
        "Failed for variant: #{variant}")
    end
  end
end
