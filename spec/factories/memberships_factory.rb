# frozen_string_literal: true

FactoryBot.define do
  factory :membership do
    user
    tier { :free }
    starts_at { Time.current }
    active { true }

    trait :professional do
      tier { :professional }
    end

    trait :organization do
      tier { :organization }
    end

    trait :expired do
      expires_at { 1.day.ago }
    end

    trait :inactive do
      active { false }
    end

    trait :with_grantor do
      association :granted_by, factory: %i[user admin]
    end
  end
end
