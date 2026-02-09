# frozen_string_literal: true

RSpec.configure do |config|
  config.include FactoryBot::Syntax::Methods

  # Lint factories before running specs (optional, enable in CI)
  # config.before(:suite) do
  #   FactoryBot.lint
  # end
end
