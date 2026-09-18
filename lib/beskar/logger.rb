# frozen_string_literal: true

module Beskar
  # Centralized logging module for consistent log formatting and flexible output handling
  module Logger
    class << self
      # Available log levels
      LOG_LEVELS = %i[debug info warn error fatal].freeze

      # Generate logging methods for each level
      LOG_LEVELS.each do |level|
        define_method(level) do |message, component: nil|
          log(level, message, component: component)
        end
      end

      # Main logging method that handles formatting and output
      #
      # @param level [Symbol] The log level (:debug, :info, :warn, :error, :fatal)
      # @param message [String] The message to log
      # @param component [String, Symbol, nil] Optional component name for more specific prefixes
      #
      # @example Basic usage
      #   Beskar::Logger.info("User authenticated successfully")
      #   # => [Beskar] User authenticated successfully
      #
      # @example With component
      #   Beskar::Logger.warn("Rate limit exceeded", component: :WAF)
      #   # => [Beskar::WAF] Rate limit exceeded
      #
      # @example With class as component
      #   Beskar::Logger.error("Failed to lock account", component: self.class)
      #   # => [Beskar::AccountLocker] Failed to lock account
      def log(level, message, component: nil)
        return unless should_log?(level)

        formatted_message = format_message(message, component)
        logger.send(level, formatted_message)
      rescue => e
        # Fallback to stderr if logging fails
        Kernel.warn "[Beskar::Logger] Logging unavailable (#{e.class})"
      end

      # Configure the logger instance
      #
      # @param logger_instance [Logger, nil] The logger to use, defaults to Rails.logger
      attr_writer :logger

      # Get the current logger instance
      #
      # @return [Logger] The configured logger or Rails.logger as default
      def logger
        @logger ||= default_logger
      end

      # Configure log level threshold
      #
      # @param level [Symbol, String] Minimum log level to output
      def level=(level)
        @level = level.to_sym if LOG_LEVELS.include?(level.to_sym)
      end

      # Get the current log level
      #
      # @return [Symbol] Current log level
      def level
        @level ||= :debug
      end

      # Reset logger configuration to defaults
      def reset!
        @logger = nil
        @level = nil
        @component_aliases = nil
      end

      # Configure component name aliases for cleaner output
      #
      # @param aliases [Hash] Mapping of classes/modules to display names
      #
      # @example
      #   Beskar::Logger.component_aliases = {
      #     'Beskar::Services::Waf' => 'WAF',
      #     'Beskar::Services::AccountLocker' => 'AccountLocker'
      #   }
      attr_writer :component_aliases

      # Get component aliases
      #
      # @return [Hash] Current component aliases
      def component_aliases
        @component_aliases ||= default_component_aliases
      end

      private

      # Format the log message with appropriate prefix
      #
      # @param message [String] The message to format
      # @param component [String, Symbol, Class, nil] Component identifier
      # @return [String] Formatted message with prefix
      def format_message(message, component)
        prefix = build_prefix(component)
        "#{prefix} #{message}"
      end

      # Build the log prefix based on component
      #
      # @param component [String, Symbol, Class, nil] Component identifier
      # @return [String] Formatted prefix
      def build_prefix(component)
        return "[Beskar]" if component.nil?

        component_name = normalize_component_name(component)

        if component_name.nil? || component_name.empty?
          "[Beskar]"
        else
          "[Beskar::#{component_name}]"
        end
      end

      # Normalize component name from various input types
      #
      # @param component [String, Symbol, Class] Component identifier
      # @return [String, nil] Normalized component name
      def normalize_component_name(component)
        case component
        when String
          apply_component_alias(component)
        when Symbol
          component.to_s
        when Class
          apply_component_alias(component.name)
        when Module
          apply_component_alias(component.name)
        else
          component.to_s
        end
      end

      # Apply component alias if configured
      #
      # @param component_name [String] Original component name
      # @return [String] Aliased name or original
      def apply_component_alias(component_name)
        return nil if component_name.nil?

        # First check exact matches
        aliased = component_aliases[component_name]
        return aliased if aliased

        # Remove Beskar:: prefix if present for lookup
        clean_name = component_name.sub(/^Beskar::/, "")
        aliased = component_aliases[clean_name]
        return aliased if aliased

        # Check if it's already a simple component name (no ::)
        return clean_name unless clean_name.include?("::")

        # Extract the last component for nested classes
        # e.g., "Beskar::Services::Waf" -> "Waf"
        last_component = clean_name.split("::").last
        component_aliases[clean_name] || last_component
      end

      # Check if message should be logged based on current level
      #
      # @param message_level [Symbol] Level of the message
      # @return [Boolean] True if message should be logged
      def should_log?(message_level)
        level_value(message_level) >= level_value(level)
      end

      # Convert log level to numeric value for comparison
      #
      # @param level_sym [Symbol] Log level
      # @return [Integer] Numeric value
      def level_value(level_sym)
        LOG_LEVELS.index(level_sym) || 0
      end

      # Get the default logger instance
      #
      # @return [Logger] Default logger (Rails.logger or stdlib Logger)
      def default_logger
        if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
          Rails.logger
        else
          require "logger"
          ::Logger.new($stdout)
        end
      end

      # Default component name aliases for cleaner output
      #
      # @return [Hash] Default aliases
      def default_component_aliases
        {
          "Beskar::Services::Waf" => "WAF",
          "Beskar::Services::WAF" => "WAF",
          "Services::Waf" => "WAF",
          "Services::WAF" => "WAF",
          "Beskar::Services::AccountLocker" => "AccountLocker",
          "Services::AccountLocker" => "AccountLocker",
          "Beskar::Services::RateLimiter" => "RateLimiter",
          "Services::RateLimiter" => "RateLimiter",
          "Beskar::Services::IpWhitelist" => "IpWhitelist",
          "Services::IpWhitelist" => "IpWhitelist",
          "Beskar::Services::GeolocationService" => "GeolocationService",
          "Services::GeolocationService" => "GeolocationService",
          "Beskar::Services::DeviceDetector" => "DeviceDetector",
          "Services::DeviceDetector" => "DeviceDetector",
          "Beskar::Middleware::RequestAnalyzer" => "Middleware",
          "Middleware::RequestAnalyzer" => "Middleware",
          "Beskar::Models::SecurityTrackableDevise" => "SecurityTracking",
          "Models::SecurityTrackableDevise" => "SecurityTracking",
          "Beskar::Models::SecurityTrackableAuthenticable" => "SecurityTracking",
          "Models::SecurityTrackableAuthenticable" => "SecurityTracking",
          "Beskar::Models::SecurityTrackableGeneric" => "SecurityTracking",
          "Models::SecurityTrackableGeneric" => "SecurityTracking"
        }
      end
    end

    # Module to include in classes for instance-level logging
    module ClassMethods
      # Log a debug message with automatic component detection
      def log_debug(message)
        Beskar::Logger.debug(message, component: self)
      end

      # Log an info message with automatic component detection
      def log_info(message)
        Beskar::Logger.info(message, component: self)
      end

      # Log a warning message with automatic component detection
      def log_warn(message)
        Beskar::Logger.warn(message, component: self)
      end

      # Log an error message with automatic component detection
      def log_error(message)
        Beskar::Logger.error(message, component: self)
      end

      # Log a fatal message with automatic component detection
      def log_fatal(message)
        Beskar::Logger.fatal(message, component: self)
      end
    end

    # Module to include in classes for instance-level logging
    module InstanceMethods
      # Log a debug message with automatic component detection
      def log_debug(message)
        Beskar::Logger.debug(message, component: self.class)
      end

      # Log an info message with automatic component detection
      def log_info(message)
        Beskar::Logger.info(message, component: self.class)
      end

      # Log a warning message with automatic component detection
      def log_warn(message)
        Beskar::Logger.warn(message, component: self.class)
      end

      # Log an error message with automatic component detection
      def log_error(message)
        Beskar::Logger.error(message, component: self.class)
      end

      # Log a fatal message with automatic component detection
      def log_fatal(message)
        Beskar::Logger.fatal(message, component: self.class)
      end
    end

    # Convenience method to include both class and instance methods
    def self.included(base)
      base.extend(ClassMethods)
      base.include(InstanceMethods)
    end
  end
end
