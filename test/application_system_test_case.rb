require "test_helper"
require "action_dispatch/system_test_case"
require "selenium-webdriver"

class ApplicationSystemTestCase < ActionDispatch::SystemTestCase
  parallelize(workers: 1)
  Capybara.enable_aria_label = true

  # Prefer an installed driver; never require a browser download on this machine.
  driver_path = ENV["BESKAR_BROWSER_DRIVER"] || ENV.fetch("PATH").split(File::PATH_SEPARATOR)
    .map { |directory| File.join(directory, "chromedriver") }.find { |path| File.executable?(path) }
  Selenium::WebDriver::Chrome::Service.driver_path = driver_path if driver_path

  driver_options = {}
  if (log_path = ENV["BESKAR_BROWSER_LOG"].presence)
    FileUtils.mkdir_p(File.dirname(log_path))
    driver_options[:service] = Selenium::WebDriver::Service.chrome(
      path: driver_path, log: log_path, args: ["--verbose", "--append-log"]
    )
  end

  driven_by :selenium, using: :headless_chrome, screen_size: [1440, 1200], options: driver_options do |options|
    binary = ENV["BESKAR_BROWSER_BINARY"] || %w[/usr/bin/chromium /usr/bin/google-chrome].find { |path| File.executable?(path) }
    options.binary = binary if binary
    options.add_option("goog:loggingPrefs", {browser: "ALL"})
  end

  setup do
    @original_forgery_protection = Beskar::ApplicationController.allow_forgery_protection
    @browser_started = false
    page.driver.browser.manage.window.size = Selenium::WebDriver::Dimension.new(1440, 1200)
    @browser_started = true
    Beskar::ApplicationController.allow_forgery_protection = true
    Beskar.configure do |config|
      config.authenticate_admin = ->(_) { true }
      config.audit_actor = ->(_) { "test:browser" }
    end
  end

  teardown do
    Beskar::ApplicationController.allow_forgery_protection = @original_forgery_protection
    # Do not launch another browser while cleaning up a failed startup.
    page.driver.quit if @browser_started
  end

  def take_failed_screenshot
    super if @browser_started
  end

  private

  def browser_timezone(name)
    page.driver.browser.execute_cdp("Emulation.setTimezoneOverride", timezoneId: name)
  end

  def assert_no_script_errors(expected_http_status: nil)
    errors = page.driver.browser.logs.get(:browser).select { |entry| entry.level == "SEVERE" && !entry.message.match?(%r{/favicon\.ico\b.*404}) }
    if expected_http_status
      errors.reject! { |entry| entry.message.include?(" - Failed to load resource: the server responded with a status of #{expected_http_status} ") }
    end
    assert_empty errors, errors.map(&:message).join("\n")
  end

  def load_host_turbo
    source = File.join(Gem.loaded_specs.fetch("turbo-rails").full_gem_path, "app/assets/javascripts/turbo.js")
    page.execute_script(<<~JS, File.read(source))
      const script = document.createElement('script');
      script.type = 'module';
      script.nonce = document.querySelector('script[nonce]').nonce;
      script.dataset.testTurbo = 'true';
      script.addEventListener('load', () => { script.dataset.loaded = 'true'; });
      script.textContent = arguments[0];
      document.head.append(script);
    JS
    Selenium::WebDriver::Wait.new(timeout: 5).until { page.evaluate_script("!!window.Turbo") }
    assert page.evaluate_script("!!window.Turbo")
  rescue Selenium::WebDriver::Error::TimeoutError
    flunk page.driver.browser.logs.get(:browser).map(&:message).join("\n")
  end
end
