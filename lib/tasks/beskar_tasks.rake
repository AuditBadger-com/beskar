# frozen_string_literal: true

namespace :beskar do
  desc "Remove expired coordination state (does not remove audit events or active bans)"
  task cleanup_security_state: :environment do
    Beskar::SecurityState.cleanup_expired!
  end

  desc "Install Beskar: copy migrations and create initializer"
  task install: :environment do
    puts "=" * 80
    puts "Installing Beskar Security..."
    puts "=" * 80
    puts

    # Copy migrations
    puts "📦 Copying migrations..."
    Rake::Task["beskar:install:migrations"].invoke
    puts "✓ Migrations ready"
    puts

    # Create initializer
    initializer_path = Rails.root.join("config/initializers/beskar.rb")

    if File.exist?(initializer_path)
      puts "⚠️  Initializer already exists at config/initializers/beskar.rb"
      print "   Overwrite? (y/N): "
      response = $stdin.gets.to_s.strip.downcase

      unless response == "y" || response == "yes"
        puts "   Skipping initializer creation"
        puts
        next_steps
        exit
      end
    end

    puts "📝 Creating initializer..."
    template_path = File.expand_path("../generators/beskar/install/templates/initializer.rb.tt", __dir__)

    # Read the template and process ERB (Rails will be available in the rake task context)
    template_content = File.read(template_path)
    erb = ERB.new(template_content, trim_mode: "-")

    # Evaluate the ERB template in a context where Rails is available
    processed_content = erb.result(binding)

    # Write the processed initializer
    File.write(initializer_path, processed_content)
    puts "✓ Created config/initializers/beskar.rb"
    puts

    next_steps
  end

  def next_steps
    puts "=" * 80
    puts "Beskar Security has been installed!"
    puts "=" * 80
    puts
    puts "Next steps:"
    puts
    puts "1. Run migrations to create the security tables:"
    puts
    puts "   bin/rails db:migrate"
    puts
    puts "2. Add the SecurityTrackable concern to your User model:"
    puts
    puts "   # app/models/user.rb"
    puts "   class User < ApplicationRecord"
    puts "     include Beskar::Models::SecurityTrackable"
    puts "     "
    puts "     devise :database_authenticatable, :registerable,"
    puts "            :recoverable, :rememberable, :validatable"
    puts "     # ... rest of your Devise modules"
    puts "   end"
    puts
    puts "3. Review the configuration file:"
    puts
    puts "   config/initializers/beskar.rb"
    puts
    puts "   By default, WAF is enabled in MONITOR-ONLY MODE. This means:"
    puts "   - Vulnerability scans are detected and logged"
    puts "   - No requests are blocked yet"
    puts "   - Security events are created for analysis"
    puts
    puts "4. Monitor WAF activity (recommended for 24-48 hours):"
    puts
    puts "   # View all WAF logs"
    puts "   tail -f log/production.log | grep \"Beskar::WAF\""
    puts "   "
    puts "   # Check what would be blocked"
    puts "   rails console"
    puts "   > Beskar::SecurityEvent.where(event_type: 'waf_violation')"
    puts "       .where(\"metadata->>'would_be_blocked' = ?\", 'true').count"
    puts
    puts "5. When ready to enable blocking:"
    puts
    puts "   # config/initializers/beskar.rb"
    puts "   config.waf[:enabled] = true"
    puts "   config.monitor_only = false"
    puts
    puts "6. Optional: Add IP whitelist for trusted sources:"
    puts
    puts "   # config/initializers/beskar.rb"
    puts "   config.ip_whitelist = ["
    puts "     \"YOUR_OFFICE_IP\","
    puts "     \"YOUR_MONITORING_SERVICE_IP\""
    puts "   ]"
    puts
    puts "=" * 80
    puts "Documentation:"
    puts "  - README: https://github.com/humadroid-io/beskar"
    puts "  - WAF Monitor Mode: See docs/operations/monitor-only-mode.md"
    puts "=" * 80
  end
end
