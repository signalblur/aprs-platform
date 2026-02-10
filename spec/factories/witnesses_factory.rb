# frozen_string_literal: true

FactoryBot.define do
  factory :witness do
    sighting
    name { Faker::Name.name }
    contact_info { Faker::Internet.email }

    trait :anonymous do
      name { nil }
      contact_info { nil }
    end

    trait :with_statement do
      statement { Faker::Lorem.paragraph_by_chars(number: 200) }
    end

    trait :with_credibility_notes do
      credibility_notes { Faker::Lorem.paragraph }
    end
  end
end
