# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record/migration"

module Beskar
  module Generators
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      desc "Creates a Beskar initializer, mounts the dashboard, and copies migrations"

      def copy_initializer
        template "initializer.rb.tt", "config/initializers/beskar.rb"
      end

      def mount_engine
        route_text = "mount Beskar::Engine => '/beskar'"

        # Check if the route already exists
        routes_path = File.join(destination_root, "config/routes.rb")
        if !File.exist?(routes_path)
          say "No config/routes.rb found; mount Beskar::Engine manually at /beskar.", :yellow
        elsif File.read(routes_path).match?(/\bmount\s+Beskar::Engine\b/)
          say "Route already mounted, skipping...", :yellow
        else
          route route_text
          say "Mounted Beskar engine at /beskar", :green
        end
      end

      def copy_migrations
        # Copy migrations from the engine to the host app
        migration_source = File.expand_path("../../../../db/migrate", __dir__)

        if Dir.exist?(migration_source)
          Dir.glob("#{migration_source}/*.rb").each do |migration|
            migration_name = File.basename(migration).sub(/^\d+_/, "")

            # Check if migration already exists
            if migration_already_exists?(migration_name)
              say "Migration #{migration_name} already exists, skipping...", :yellow
            else
              migration_template migration, "db/migrate/#{migration_name}"
            end
          end
        end

        say "Migrations copied. Run 'rails db:migrate' to create the tables.", :green
      end

      # CSS Zero is no longer required - styles are embedded in the dashboard
      # def install_css_zero
      #   # Removed - dashboard now uses embedded styles
      # end

      def show_readme
        readme_content = <<~README

          ===============================================================================
          🛡️  Beskar Installation Complete!
          ===============================================================================

          Next steps:

          1. Run migrations to create the security tables:
             $ rails db:migrate

          2. Configure authentication for the dashboard in config/initializers/beskar.rb

             Uncomment one complete example in the generated initializer:
             - Rails built-in authentication: signed session_id cookie and Session model.
             - Devise: Warden authentication with your app's Devise mapping scope.

             Each example includes authenticate_admin, authorize_admin, and audit_actor.
             Adapt admin? and beskar_permissions to your application's roles/policies.
             Permissions: read, manage_bans, export, read_audit. Missing grants deny access.
             Beskar's controller does not inherit your host authentication helpers.
             See docs/guides/authentication.md and docs/guides/audit-lifecycle.md.
             Without audit_actor, separately authorized reads work but writes/exports return 503.

          3. Add Beskar concerns to your User model (or authentication model):

             For Rails built-in authentication:
             class User < ApplicationRecord
               include Beskar::Models::SecurityTrackableAuthenticable
             end
             Also integrate login admission and session guards from docs/guides/authentication.md.

             For Devise:
             class User < ApplicationRecord
               include Beskar::Models::SecurityTrackable
               include Beskar::Models::SecurityTrackableDevise
             end

          4. Access the security dashboard at:
             http://localhost:3000/beskar

          5. Optional: Configure additional settings in config/initializers/beskar.rb
             - IP whitelist
             - WAF rules
             - Rate limiting
             - Geolocation
             - Risk-based locking

          ===============================================================================
          📚 Documentation
          ===============================================================================

          Documentation: https://github.com/humadroid-io/beskar/blob/master/docs/README.md
          Dashboard Guide: https://github.com/humadroid-io/beskar/blob/master/docs/guides/dashboard-and-search.md
          Configuration: https://github.com/humadroid-io/beskar/blob/master/docs/guides/configuration.md

          ===============================================================================
          ⚠️  Important for Production
          ===============================================================================

          1. ALWAYS configure authentication for the dashboard
          2. Set monitor_only = false when ready to block threats
          3. Configure your IP whitelist to prevent locking yourself out
          4. Run the copied migrations; required indexes are included.
          5. Schedule Beskar::SecurityState.cleanup_expired! to reclaim expired state.

          ===============================================================================
          💡 Quick Tips
          ===============================================================================

          - Start with monitor_only = true to observe without blocking
          - Use the dashboard to review security events before enabling blocking
          - Configure email notifications for high-risk events
          - Export security data regularly for analysis
          - Consider implementing custom risk scoring for your use case

          ===============================================================================

        README

        say readme_content, :green
      end

      private

      def migration_already_exists?(migration_name)
        basename = migration_name.delete_suffix(".rb")
        Dir.glob(File.join(destination_root, "db/migrate/*_#{basename}{,.beskar}.rb")).any?
      end

      def migration_template(source, destination)
        migration_number = self.class.next_migration_number(File.join(destination_root, File.dirname(destination)))
        file_name = File.join(File.dirname(destination), "#{migration_number}_#{File.basename(destination)}")

        copy_file source, file_name
      end
    end
  end
end
