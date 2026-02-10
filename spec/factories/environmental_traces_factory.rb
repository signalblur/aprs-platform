# frozen_string_literal: true

FactoryBot.define do
  factory :environmental_trace do
    sighting
    trace_type { "ground_marking" }
    description { Faker::Lorem.paragraph }

    trait :with_location do
      location { "POINT(-104.9903 39.7392)" }
    end

    trait :with_measurement do
      measured_value { "2.5" }
      measurement_unit { "mSv/hr" }
    end

    trait :without_optional_fields do
      description { nil }
      location { nil }
      measured_value { nil }
      measurement_unit { nil }
    end
  end
end
