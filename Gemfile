source "https://rubygems.org"

# Specify your gem's dependencies in beskar.gemspec.
gemspec

gem "puma"

gem "sqlite3"

gem "propshaft"

# Standard Ruby styling [https://github.com/standardrb/standard]
gem "standard", require: false

# Rails 8.0's test runner uses the Minitest 5 runner API.
gem "minitest", "~> 5.25"

# Start debugger with binding.b [https://github.com/ruby/debug]
# gem "debug", ">= 1.0.0"

gem "devise"

gem "bcrypt", "~> 3.1.22"

gem "debug"

group :test do
  gem "pg", "~> 1.5", require: false
  gem "mysql2", "~> 0.5", require: false
  gem "capybara", "~> 3.40"
  gem "selenium-webdriver", "~> 4.0"
  gem "turbo-rails", "~> 2.0", require: false
end
