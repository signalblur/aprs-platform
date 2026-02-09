# frozen_string_literal: true

FactoryBot.define do
  factory :user do
    email { Faker::Internet.email }
    password { "SecurePass123!" }
    confirmed_at { Time.current }

    trait :member do
      role { :member }
    end

    trait :investigator do
      role { :investigator }
    end

    trait :admin do
      role { :admin }
    end
  end
end
