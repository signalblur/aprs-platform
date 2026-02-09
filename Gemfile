source "https://rubygems.org"

ruby "3.4.8"

# Core Framework
gem "rails", "~> 8.1.2"
gem "propshaft"
gem "puma", ">= 5.0"

# Database
gem "pg", "~> 1.1"
gem "activerecord-postgis-adapter"

# Frontend
gem "importmap-rails"
gem "turbo-rails"
gem "stimulus-rails"
gem "tailwindcss-rails"

# Authentication & Authorization
gem "devise"
gem "pundit"

# Payments
gem "stripe"

# Geospatial
gem "rgeo"
gem "rgeo-geojson"

# Background Jobs (Rails 8 built-in)
gem "solid_cache"
gem "solid_queue"
gem "solid_cable"

# File Storage
gem "image_processing", "~> 1.2"
gem "aws-sdk-s3", require: false

# API Documentation
gem "rswag-api"
gem "rswag-ui"

# Charts (Admin Dashboard)
gem "chartkick"
gem "groupdate"

# Misc
gem "bootsnap", require: false
gem "tzinfo-data", platforms: %i[windows jruby]

group :development, :test do
  gem "debug", platforms: %i[mri windows], require: "debug/prelude"

  # Testing
  gem "rspec-rails"
  gem "factory_bot_rails"
  gem "faker"
  gem "shoulda-matchers"

  # API Documentation (test generators)
  gem "rswag-specs"

  # Security
  gem "bundler-audit", require: false
  gem "brakeman", require: false

  # Linting
  gem "rubocop", require: false
  gem "rubocop-rails", require: false
  gem "rubocop-rspec", require: false
  gem "rubocop-rails-omakase", require: false

  # Environment
  gem "dotenv-rails"
end

group :test do
  gem "simplecov", require: false
  gem "webmock"
  gem "vcr"
end

group :development do
  gem "web-console"
  gem "letter_opener_web"
end
