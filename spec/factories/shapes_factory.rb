# frozen_string_literal: true

FactoryBot.define do
  factory :shape do
    sequence(:name) { |n| "Shape #{n}" }
    description { Faker::Lorem.sentence }

    trait :without_description do
      description { nil }
    end
  end
end
