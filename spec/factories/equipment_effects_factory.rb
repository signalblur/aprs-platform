# frozen_string_literal: true

FactoryBot.define do
  factory :equipment_effect do
    sighting
    equipment_type { "car_engine" }
    effect_type { "malfunction" }
    description { Faker::Lorem.paragraph }

    trait :without_description do
      description { nil }
    end
  end
end
