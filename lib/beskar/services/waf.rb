module Beskar
  module Services
    class Waf
      RULES_VERSION = 1
      # Root/segment boundaries prevent matches inside ordinary words. Matching
      # uses a decoded path, not arbitrary query values; dot segments are retained.
      VULNERABILITY_PATTERNS = {
        rails_exceptions: {
          patterns: [%r{/(?:users?|posts?|articles?|comments?|api/v\d+/\w+)/\d+\.(?:exe|bat|cmd|com|scr|vbs|jar|app|deb|rpm)\z}i,
            %r{/(?:users?|posts?|articles?|comments?|api/v\d+/\w+)\.(?:asp|aspx|jsp|do|action|cgi|pl|py|rb)\z}i],
          severity: :medium, description: "Potential Rails exception triggering attempt"
        },
        record_scanning: {
          patterns: [%r{/(?:user|admin|account|profile|order|payment|invoice|document|file|download)/\d{6,}(?:/|\z)}i,
            %r{\A/(?:user|admin|account|profile)/(?:test|admin|root|administrator|superuser)(?:/|\z)}i,
            %r{/api/v\d+/(?:users?|accounts?|orders?|payments?)/(?:999999|123456|0|null|undefined)(?:/|\z)}i],
          severity: :low, description: "Potential record enumeration/scanning"
        },
        wordpress: {
          patterns: [%r{/wp-admin(?:/|\z)}i, %r{/wp-login\.php(?:/|\z)}i,
            %r{/wp-content/.*\.php(?:/|\z)}i, %r{/wp-includes(?:/|\z)}i,
            %r{/xmlrpc\.php(?:/|\z)}i, %r{/wp-config\.(?:php|bak)(?:/|\z)}i,
            %r{\A/wordpress(?:/|\z)}i],
          severity: :high, description: "WordPress vulnerability scan"
        },
        wordpress_static: {
          patterns: [%r{/wp-content/.*\.(?:css|js|jpe?g|png|gif|svg|webp|ico|woff2?|ttf|eot|map)\z}i,
            %r{/wp-content/(?:uploads|themes|plugins)/[^.]*\z}i],
          severity: :low, description: "WordPress static file probe"
        },
        php_admin: {
          patterns: [%r{\A/(?:phpmyadmin|pma|administrator)(?:/|\z)}i,
            %r{/(?:admin|phpinfo)\.php(?:/|\z)}i, %r{/admin/config\.php(?:/|\z)}i],
          severity: :high, description: "PHP admin panel scan"
        },
        config_files: {
          patterns: [%r{/(?:\.env(?:\.[a-z0-9_-]+)?|\.git)(?:/|\z)}i,
            %r{/(?:config|configuration|settings)\.php(?:/|\z)}i,
            %r{/(?:database|credentials)\.yml(?:\.enc)?(?:/|\z)}i],
          severity: :critical, description: "Configuration file access attempt"
        },
        path_traversal: {
          patterns: [%r{/(?:etc/(?:passwd|shadow|hosts))(?:/|\z)}i, %r{(?:\A|/)\.\.(?:/|\z)}],
          severity: :critical, description: "Path traversal attempt"
        },
        framework_debug: {
          patterns: [%r{\A/(?:rails/info/routes|__debug__|debug|telescope|_profiler)(?:/|\z)}],
          severity: :medium, description: "Framework debug endpoint scan"
        },
        cms_scan: {
          patterns: [%r{\A/(?:joomla|drupal|magento|prestashop|typo3)(?:/|\z)}i],
          severity: :medium, description: "CMS detection scan"
        },
        common_exploits: {
          patterns: [%r{/(?:shell|cmd|c99|r57)\.php(?:/|\z)}i, %r{/(?:backdoor|webshell)(?:/|\z)}i],
          severity: :critical, description: "Common exploit file access"
        }
      }.freeze

      EXCEPTION_RULES = {
        "ActionController::UnknownFormat" => [:unknown_format, :medium, "Unknown format requested - potential scanner"],
        "ActionDispatch::RemoteIp::IpSpoofAttackError" => [:ip_spoof, :critical, "IP spoofing attack detected"],
        "ActiveRecord::RecordNotFound" => [:record_not_found, :low, "Record not found - potential enumeration scan"],
        "ActionDispatch::Http::MimeNegotiation::InvalidType" => [:invalid_mime_type, :medium, "Invalid MIME type requested - potential scanner"]
      }.freeze

      # Configuration for RecordNotFound exclusion patterns
      # These patterns will not trigger WAF violations
      RECORD_NOT_FOUND_EXCLUSIONS = [
        # Add default exclusions here if needed
        # %r{/posts/.*},  # Example: exclude all posts paths
      ].freeze

      class << self
        # Analyze a request for vulnerability scanning patterns
        def analyze_request(request)
          input = WafRequest.new(request)
          return nil if input.path.blank? && !input.problem
          patterns = []
          if input.problem && !input.excluded?(:malformed_path)
            patterns << {category: :malformed_path, rule_id: "malformed_path:#{input.problem}",
                         severity: :medium, description: "Malformed or oversized request path"}
          end
          VULNERABILITY_PATTERNS.each do |category, config|
            next if input.excluded?(category)
            config[:patterns].each_with_index do |pattern, index|
              next unless input.path.match?(pattern)
              patterns << {category: category, rule_id: "#{category}:#{index}", severity: config[:severity], description: config[:description]}
            end
          end
          if input.suspicious_format? && !input.excluded?(:rails_exceptions)
            patterns << {category: :rails_exceptions, rule_id: "rails_exceptions:format",
                         severity: :medium, description: VULNERABILITY_PATTERNS[:rails_exceptions][:description]}
          end
          analysis_for(request, input, patterns) if patterns.any?
        end

        def analyze_exception(exception, request)
          rule = EXCEPTION_RULES[exception.class.name]
          return unless rule
          category, severity, description = rule
          input = WafRequest.new(request)
          return if input.excluded?(category)
          return if category == :record_not_found && should_exclude_record_not_found?(input.path)
          policy = waf_config.fetch(:exception_detection, :suspicious)
          return if policy == :none
          # A Rails error alone is not proof of abuse. Broad legacy scoring must
          # be opted into; resolved IP-spoof exceptions remain a distinct signal.
          return unless policy == :all || category == :ip_spoof || analyze_request(request)
          analysis_for(request, input, [{category: category, rule_id: "exception:#{category}",
                                         severity: severity, description: description}])
            .merge(exception_class: exception.class.name)
        end

        # Check if a RecordNotFound exception should be excluded from WAF
        def should_exclude_record_not_found?(path)
          return false if path.blank?

          # Check configured exclusions
          exclusions = waf_config[:record_not_found_exclusions] || []
          all_exclusions = RECORD_NOT_FOUND_EXCLUSIONS + exclusions

          all_exclusions.any? { |pattern| path.match?(pattern) }
        end

        # Check if request should be blocked based on violation history
        def should_block?(ip_address)
          config = waf_config
          return false unless config[:enabled]
          return false unless config[:auto_block]

          # Get current risk score (with decay applied)
          current_score = get_current_score(ip_address)
          threshold = config[:score_threshold] || 150

          current_score >= threshold
        end

        # Record a WAF violation
        def record_violation(ip_address, analysis_result, whitelisted: false)
          config = waf_config
          return unless config[:enabled]

          Beskar::Logger.debug("[WAF] Recording violation for IP: #{ip_address}, whitelisted: #{whitelisted}", component: :WAF)

          analysis_result = sanitized_analysis(analysis_result)
          key = state_key(ip_address, whitelisted: whitelisted)
          risk_score = severity_to_risk_score(analysis_result[:highest_severity])
          violations, current_score = SecurityState.mutate(key, ttl: config[:violation_window] || 6.hours) do |state|
            entries = Array(state[key]["violations"]).map { |entry| entry.deep_symbolize_keys.slice(:timestamp, :score, :severity, :category, :rule_id) }
            entries << {
              timestamp: Time.current.to_i,
              score: risk_score,
              severity: analysis_result[:highest_severity],
              category: analysis_result[:patterns].first[:category],
              rule_id: analysis_result[:patterns].first[:rule_id]
            }
            entries = prune_violations(entries, config)
            state[key]["violations"] = entries
            [entries, calculate_current_score(entries, config)]
          end

          # Log the violation
          log_violation(ip_address, analysis_result, current_score, violations.size)

          # Create security event if configured
          if config[:create_security_events]
            create_security_event(ip_address, analysis_result, current_score, whitelisted: whitelisted, violation_count: violations.size)
          end

          # Check if we should auto-block (skip if whitelisted)
          threshold = config[:score_threshold] || 150

          Beskar::Logger.debug("[WAF] Auto-block check: whitelisted=#{whitelisted}, auto_block=#{config[:auto_block]}, score=#{current_score.round(2)}, threshold=#{threshold}", component: :WAF)

          if !whitelisted && !IpWhitelist.whitelisted?(ip_address) && config[:auto_block] && current_score >= threshold
            if Beskar.configuration.monitor_only?
              log_monitor_only_action(ip_address, analysis_result, current_score, threshold)
            else
              auto_block_ip(ip_address, analysis_result, current_score)
            end
          end

          current_score
        end

        # Get current risk score for an IP (with decay applied)
        def get_current_score(ip_address)
          violations = get_violations(ip_address)
          calculate_current_score(violations, waf_config)
        end

        # Get violations for an IP
        def get_violations(ip_address)
          entries = Array(SecurityState.read(state_key(ip_address))["violations"]).map { |entry| entry.deep_symbolize_keys.slice(:timestamp, :score, :severity, :category, :rule_id) }
          prune_violations(entries, waf_config)
        end

        # Get violation count for an IP (number of violations tracked)
        def get_violation_count(ip_address)
          get_violations(ip_address).size
        end

        # Reset violations for an IP
        def reset_violations(ip_address)
          ip_address = IPAddr.new(ip_address.to_s).to_s
          keys = ["waf:enforce:#{ip_address}", "waf:observe:#{ip_address}"]
          SecurityState.mutate(keys, ttl: 1.second) { |state| state.each_value(&:clear) }
        end

        private

        def analysis_for(request, input, patterns)
          {threat_detected: true, patterns: patterns, highest_severity: calculate_highest_severity(patterns),
           ip_address: RequestContext.ip(request), request_method: input.method, rules_version: RULES_VERSION,
           decoding_passes: input.decoding_passes, timestamp: Time.current}
        end

        # A public caller may supply an old-style analysis containing raw URLs
        # or exception messages. Project onto rule evidence before any sink.
        def sanitized_analysis(analysis)
          severities = %i[critical high medium low]
          severity = severities.find { |level| level.to_s == analysis[:highest_severity].to_s }
          raise ArgumentError, "WAF analysis requires a valid severity" unless severity
          passes = analysis[:decoding_passes]
          result = {threat_detected: true, highest_severity: severity, rules_version: RULES_VERSION,
                    decoding_passes: (passes.is_a?(Integer) && (0..2).cover?(passes)) ? passes : 0, timestamp: Time.current}
          categories = VULNERABILITY_PATTERNS.keys + EXCEPTION_RULES.values.map(&:first) + [:malformed_path]
          result[:patterns] = Array(analysis[:patterns]).first(32).map do |pattern|
            category = categories.find { |value| value.to_s == pattern[:category].to_s } || :custom
            config = VULNERABILITY_PATTERNS[category]
            exception = EXCEPTION_RULES.values.find { |rule| rule.first == category }
            description = config&.fetch(:description) || exception&.last || "Custom WAF rule"
            ids = config ? config[:patterns].each_index.map { |index| "#{category}:#{index}" } : []
            ids << "rails_exceptions:format" if category == :rails_exceptions
            ids << "exception:#{category}" if exception
            ids.concat(%w[oversized_path invalid_encoding excessive_encoding].map { |problem| "malformed_path:#{problem}" }) if category == :malformed_path
            rule_id = ids.include?(pattern[:rule_id]) ? pattern[:rule_id] : "custom"
            {category: category, rule_id: rule_id, severity: severities.find { |value| value.to_s == pattern[:severity].to_s } || severity, description: description}
          end
          raise ArgumentError, "WAF analysis requires matched rules" if result[:patterns].empty?
          result[:exception_class] = analysis[:exception_class] if EXCEPTION_RULES.key?(analysis[:exception_class])
          result[:request_method] = analysis[:request_method] if %w[GET HEAD POST PUT PATCH DELETE OPTIONS CONNECT TRACE OTHER].include?(analysis[:request_method])
          result
        end

        def state_key(ip_address, whitelisted: false)
          mode = (Beskar.configuration.monitor_only? || whitelisted || IpWhitelist.whitelisted?(ip_address)) ? "observe" : "enforce"
          "waf:#{mode}:#{IPAddr.new(ip_address.to_s)}"
        end

        # Calculate current cumulative score with decay applied
        def calculate_current_score(violations, config)
          return 0.0 if violations.empty?
          return violations.sum { |v| v[:score] } unless config[:decay_enabled]

          now = Time.current.to_i
          decay_rates = config[:decay_rates] || {}

          violations.sum do |v|
            age_seconds = now - v[:timestamp]
            age_minutes = age_seconds / 60.0

            # Get half-life for this severity (in minutes)
            half_life = decay_rates[v[:severity].to_sym] || 60

            # Exponential decay: score * (1/2)^(age/half_life)
            # Equivalent to: score * e^(-ln(2) * age / half_life)
            decay_factor = Math.exp(-Math.log(2) * age_minutes / half_life)

            v[:score] * decay_factor
          end
        end

        # Prune violations that are outside the window or exceed max tracked
        def prune_violations(violations, config)
          now = Time.current.to_i
          window_seconds = (config[:violation_window] || 6.hours).to_i
          max_tracked = config[:max_violations_tracked] || 50

          # Remove violations outside the time window
          recent = violations.select do |v|
            (now - v[:timestamp]) <= window_seconds
          end

          # Keep only the most recent violations if we exceed max_tracked
          if recent.size > max_tracked
            recent.sort_by { |v| -v[:timestamp] }.first(max_tracked)
          else
            recent
          end
        end

        # Get WAF configuration
        def waf_config
          Beskar.configuration.waf || {}
        end

        # Calculate highest severity from detected patterns
        def calculate_highest_severity(patterns)
          severities = patterns.map { |p| p[:severity] }
          return :critical if severities.include?(:critical)
          return :high if severities.include?(:high)
          return :medium if severities.include?(:medium)
          :low
        end

        # Log WAF violation
        def log_violation(ip_address, analysis_result, current_score, violation_count)
          severity_emoji = {
            critical: "🚨",
            high: "⚠️",
            medium: "⚡",
            low: "ℹ️"
          }

          emoji = severity_emoji[analysis_result[:highest_severity]] || "🔍"
          waf_config
          monitor_mode_notice = Beskar.configuration.monitor_only? ? " [MONITOR-ONLY MODE]" : ""

          Beskar::Logger.warn("#{emoji} Vulnerability scan detected#{monitor_mode_notice} " \
            "(score: #{current_score.round(2)}, violations: #{violation_count}) - " \
            "IP: #{ip_address}, " \
            "Severity: #{analysis_result[:highest_severity]}, " \
            "Rules: #{analysis_result[:patterns].map { |p| p[:rule_id] }.join(", ")}", component: :WAF)
        end

        # Log what would happen in monitor-only mode (but don't actually block)
        def log_monitor_only_action(ip_address, analysis_result, current_score, threshold)
          config = waf_config
          duration = calculate_block_duration(current_score, config)

          Beskar::Logger.warn("🔍 MONITOR-ONLY: IP #{ip_address} WOULD BE BLOCKED " \
            "(score threshold reached: #{current_score.round(2)}/#{threshold}) - " \
            "Duration would be: #{duration ? "#{duration / 3600.0} hours" : "PERMANENT"}, " \
            "Severity: #{analysis_result[:highest_severity]}, " \
            "Patterns: #{analysis_result[:patterns].map { |p| p[:description] }.join(", ")}. " \
            "To enable blocking, set config.monitor_only = false", component: :WAF)
        end

        # Create security event for WAF violation
        def create_security_event(ip_address, analysis_result, current_score, whitelisted: false, violation_count: nil)
          config = waf_config
          violation_count ||= get_violation_count(ip_address)
          threshold = config[:score_threshold] || 150
          would_be_blocked = config[:auto_block] && !whitelisted && !IpWhitelist.whitelisted?(ip_address) && current_score >= threshold

          Beskar::SecurityEvent.transaction(requires_new: true) do
            Beskar::SecurityEvent.create!(
              event_type: "waf_violation",
              ip_address: ip_address,
              user_agent: nil,
              risk_score: severity_to_risk_score(analysis_result[:highest_severity]),
              metadata: {
                waf_analysis: analysis_result,
                patterns_matched: analysis_result[:patterns].map { |p| p[:description] },
                severity: analysis_result[:highest_severity],
                monitor_only_mode: Beskar.configuration.monitor_only?,
                would_be_blocked: would_be_blocked,
                violation_count: violation_count,
                current_score: current_score.round(2),
                score_threshold: threshold
              }
            )
          end
        rescue => e
          Beskar::Logger.error("Failed to create security event (#{e.class})", component: :WAF)
        end

        # Auto-block an IP after threshold violations
        def auto_block_ip(ip_address, analysis_result, current_score)
          config = waf_config
          duration = calculate_block_duration(current_score, config)
          violation_count = get_violation_count(ip_address)

          Beskar::Logger.debug("[WAF] Attempting to ban IP #{ip_address} with duration: #{duration.inspect}", component: :WAF)

          begin
            banned_ip = Beskar::BannedIp.ban!(
              ip_address,
              reason: "waf_violation",
              duration: duration,
              permanent: duration.nil?,
              details: "WAF score: #{current_score.round(2)} (#{violation_count} violations) - #{analysis_result[:patterns].map { |p| p[:description] }.join(", ")}",
              metadata: {
                violation_count: violation_count,
                risk_score: current_score.round(2),
                patterns: analysis_result[:patterns],
                highest_severity: analysis_result[:highest_severity],
                blocked_at: Time.current
              }
            )

            Beskar::Logger.warn("🔒 Auto-blocked IP #{ip_address} " \
              "with score #{current_score.round(2)} (#{violation_count} violations) " \
              "(duration: #{duration ? "#{duration / 3600} hours" : "permanent"}), " \
              "Ban ID: #{banned_ip.id}", component: :WAF)
          rescue => e
            Beskar::Logger.error("[WAF] Failed to create ban for #{ip_address} (#{e.class})", component: :WAF)
            raise
          end
        end

        # Calculate block duration based on cumulative score
        def calculate_block_duration(current_score, config)
          permanent_threshold = config[:permanent_block_after]
          return nil if permanent_threshold && current_score >= permanent_threshold

          # Default escalating durations: 1h, 6h, 24h, 7d
          base_durations = config[:block_durations] || [1.hour, 6.hours, 24.hours, 7.days]
          score_threshold = config[:score_threshold] || 150

          # Calculate how many times over the threshold we are
          # 150-300 = 1x = 1 hour
          # 300-450 = 2x = 6 hours
          # 450-600 = 3x = 24 hours
          # 600+ = 4x = 7 days
          multiplier = ((current_score / score_threshold).floor - 1).clamp(0, base_durations.length - 1)
          base_durations[multiplier]
        end

        # Convert severity level to risk score
        def severity_to_risk_score(severity)
          case severity
          when :critical then 95
          when :high then 80
          when :medium then 60
          when :low then 30
          else 50
          end
        end
      end
    end
  end
end
