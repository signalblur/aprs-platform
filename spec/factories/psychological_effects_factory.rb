# frozen_string_literal: true

FactoryBot.define do
  factory :psychological_effect do
    sighting
    effect_type { "time_loss" }
    description { Faker::Lorem.paragraph }
    severity { :mild }
    onset { "days later" }
    duration { "ongoing" }

    trait :moderate do
      severity { :moderate }
    end

    trait :severe do
      severity { :severe }
    end

    trait :without_optional_fields do
      description { nil }
      onset { nil }
      duration { nil }
    end
  end
end
