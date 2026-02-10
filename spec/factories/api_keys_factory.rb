# frozen_string_literal: true

FactoryBot.define do
  factory :api_key do
    user
    name { "Test API Key" }

    trait :inactive do
      active { false }
    end

    trait :expired do
      expires_at { 1.day.ago }
    end

    trait :with_expiration do
      expires_at { 30.days.from_now }
    end
  end
end
