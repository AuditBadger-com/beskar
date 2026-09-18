require_relative "lib/beskar/version"

Gem::Specification.new do |spec|
  spec.name = "beskar"
  spec.version = Beskar::VERSION
  spec.authors = ["Maciej Litwiniuk"]
  spec.email = ["maciej@litwiniuk.net"]
  spec.homepage = "https://humadroid.io/beskar"
  spec.summary = "A Rails security engine for authentication limits, risk-based locks, IP bans, and audit events."
  spec.description = "Beskar is a mountable Rails engine with database-coordinated authentication admission limits, risk-based account locks, persistent IP bans, scanner-path signatures, and an administrative security dashboard. It supports Devise and explicit Rails-native authentication integration, optional MaxMind enrichment, User-Agent risk heuristics, and monitor-only operation. It does not implement general SQL injection or XSS filtering, JavaScript challenges, or honeypots."
  spec.license = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the "allowed_push_host"
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  # spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/humadroid-io/beskar"
  spec.metadata["documentation_uri"] = "https://github.com/humadroid-io/beskar/blob/master/docs/README.md"
  spec.metadata["changelog_uri"] = "https://github.com/humadroid-io/beskar/blob/master/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib}/**/*", "docs/**/*.md", "MIT-LICENSE", "Rakefile", "README.md", "CHANGELOG.md"]
  end

  spec.add_dependency "rails", ">= 8.0.0"
  spec.add_dependency "csv", "~> 3.0"

  # Optional: MaxMind DB reader for GeoIP functionality
  # Users need to provide their own GeoIP database due to licensing
  spec.add_dependency "maxminddb", "~> 0.1"

  spec.add_development_dependency "debug"
  spec.add_development_dependency "devise"
  spec.add_development_dependency "factory_bot_rails"
  spec.add_development_dependency "mocha"
  spec.add_development_dependency "ostruct"
end
