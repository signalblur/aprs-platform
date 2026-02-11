require_relative "boot"

require "rails"
# Pick the frameworks you want:
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
require "active_storage/engine"
require "action_controller/railtie"
require "action_mailer/railtie"
# require "action_mailbox/engine"
# require "action_text/engine"
require "action_view/railtie"
require "action_cable/engine"
# require "rails/test_unit/railtie"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module AprsPlatform
  class Application < Rails::Application
    config.load_defaults 8.1

    config.autoload_lib(ignore: %w[assets tasks])

    # Use RSpec for test generation
    config.generators.system_tests = nil
    config.generators do |g|
      g.test_framework :rspec,
        fixtures: false,
        view_specs: false,
        helper_specs: false,
        routing_specs: false
      g.factory_bot suffix: "factory"
    end

    # Filter sensitive parameters from logs
    config.filter_parameters += %i[
      password password_confirmation token api_key key secret
    ]

    # Filter PII from logs
    config.filter_parameters += %i[
      name first_name last_name contact_info phone
      latitude longitude
    ]

    # Store times in UTC
    config.time_zone = "UTC"
    config.active_record.default_timezone = :utc
  end
end
