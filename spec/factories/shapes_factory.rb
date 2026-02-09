# frozen_string_literal: true

FactoryBot.define do
  factory :shape do
    name { Faker::Lorem.unique.word.capitalize }
    description { Faker::Lorem.sentence }

    trait :without_description do
      description { nil }
    end
  end
end
