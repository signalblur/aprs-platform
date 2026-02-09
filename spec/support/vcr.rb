require "vcr"

VCR.configure do |config|
  config.cassette_library_dir = "spec/cassettes"
  config.hook_into :webmock
  config.configure_rspec_metadata!
  config.filter_sensitive_data("<STRIPE_API_KEY>") { ENV.fetch("STRIPE_API_KEY", "sk_test_fake") }
  config.filter_sensitive_data("<STRIPE_WEBHOOK_SECRET>") { ENV.fetch("STRIPE_WEBHOOK_SECRET", "whsec_fake") }
end
