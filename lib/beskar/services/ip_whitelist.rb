require "ipaddr"

module Beskar
  module Services
    class IpWhitelist
      class << self
        # Check if an IP address is whitelisted
        def whitelisted?(ip_address)
          return false if ip_address.blank?

          ip = parse_ip(ip_address)
          return false unless ip

          parsed_entries.values.any? do |entry|
            entry&.include?(ip)
          end
        rescue ArgumentError => e
          Beskar::Logger.warn("Invalid IP address: #{ip_address} - #{e.class}", component: :IpWhitelist)
          false
        end

        # Get whitelist entries from configuration
        def whitelist_entries
          entries = Beskar.configuration.ip_whitelist || []
          # Ensure it's an array
          entries = [entries] unless entries.is_a?(Array)
          entries.compact
        end

        # Clear cached whitelist (useful when config changes)
        def clear_cache!
          @parsed_snapshot = nil
        end

        # Validate whitelist configuration
        def validate_configuration!
          errors = []

          whitelist_entries.each_with_index do |entry, index|
            parse_entry(entry)
          rescue ArgumentError => e
            errors << "Entry #{index} (#{entry}): #{e.message}"
          end

          if errors.any?
            raise ConfigurationError, "Invalid IP whitelist configuration:\n#{errors.join("\n")}"
          end

          true
        end

        private

        # Parse IP address string to IPAddr object
        def parse_ip(ip_string)
          IPAddr.new(ip_string.to_s.strip)
        rescue IPAddr::InvalidAddressError
          nil
        end

        # Parse whitelist entry (can be single IP or CIDR notation)
        def parse_entry(entry)
          return nil if entry.blank?

          entry_str = entry.to_s.strip

          IPAddr.new(entry_str)
        end

        # Check if IP matches whitelist entry
        def match_entry?(ip, entry)
          parsed_entry = parsed_entries[entry]
          return false unless parsed_entry

          # IPAddr#include? handles both single IPs and CIDR ranges
          parsed_entry.include?(ip)
        rescue ArgumentError
          false
        end

        # Cache parsed entries for performance
        def parsed_entries
          source = whitelist_entries
          snapshot = @parsed_snapshot
          return snapshot.last if snapshot && snapshot.first == source

          entries = {}
          source.each do |entry|
            entries[entry] = parse_entry(entry)
          rescue ArgumentError => e
            Beskar::Logger.warn("Skipping invalid entry: #{entry} - #{e.class}", component: :IpWhitelist)
          end
          # Publish the source and parsed entries together, never a half-updated
          # cache that another request could mistake for the new configuration.
          @parsed_snapshot = [source.deep_dup, entries]
          entries
        end
      end

      # Error class for configuration issues
      class ConfigurationError < StandardError; end
    end
  end
end
