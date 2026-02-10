# frozen_string_literal: true

# Configure Rack::Attack for testing.
#
# Uses an in-memory cache store and resets state between examples
# to ensure rate limit tests are isolated.
RSpec.configure do |config|
  config.before(:suite) do
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  config.before do
    Rack::Attack.reset!
  end
end
