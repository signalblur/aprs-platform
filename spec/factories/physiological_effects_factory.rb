# frozen_string_literal: true

FactoryBot.define do
  factory :physiological_effect do
    sighting
    effect_type { "nausea" }
    description { Faker::Lorem.paragraph }
    severity { :mild }
    onset { "immediately" }
    duration { "30 minutes" }

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
