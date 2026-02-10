# frozen_string_literal: true

FactoryBot.define do
  factory :sighting do
    submitter factory: :user
    shape
    description { Faker::Lorem.paragraph_by_chars(number: 50) }
    duration_seconds { rand(5..3600) }
    location { "POINT(-104.9903 39.7392)" }
    altitude_feet { rand(100..50_000).to_d }
    observed_at { 1.day.ago }
    observed_timezone { "America/Denver" }
    num_witnesses { 1 }
    visibility_conditions { "Clear skies" }
    weather_notes { "No wind, dry conditions" }
    media_source { "Phone camera" }

    trait :anonymous do
      submitter { nil }
    end

    trait :under_review do
      status { :under_review }
    end

    trait :verified do
      status { :verified }
    end

    trait :rejected do
      status { :rejected }
    end

    trait :without_optional_fields do
      submitter { nil }
      duration_seconds { nil }
      altitude_feet { nil }
      visibility_conditions { nil }
      weather_notes { nil }
      media_source { nil }
    end

    trait :in_boulder do
      location { "POINT(-105.2705 40.0150)" }
    end

    trait :in_nyc do
      location { "POINT(-74.0060 40.7128)" }
    end
  end
end
