# frozen_string_literal: true

FactoryBot.define do
  factory :investigation do
    sequence(:case_number) { |n| format("APRS-%s-%04d", Time.current.strftime("%Y%m%d"), n) }
    title { Faker::Lorem.sentence(word_count: 5).truncate(200, omission: "") }
    description { Faker::Lorem.paragraph }
    status { :open }
    priority { :low }
    opened_at { Time.current }

    trait :with_investigator do
      assigned_investigator factory: %i[user investigator]
    end

    trait :in_progress do
      status { :in_progress }
      assigned_investigator factory: %i[user investigator]
    end

    trait :closed_resolved do
      status { :closed_resolved }
      classification { :identified }
      findings { Faker::Lorem.paragraph(sentence_count: 5) }
      closed_at { Time.current }
      assigned_investigator factory: %i[user investigator]
    end

    trait :closed_unresolved do
      status { :closed_unresolved }
      classification { :unidentified }
      findings { Faker::Lorem.paragraph(sentence_count: 5) }
      closed_at { Time.current }
      assigned_investigator factory: %i[user investigator]
    end

    trait :closed_inconclusive do
      status { :closed_inconclusive }
      classification { :insufficient_data }
      findings { Faker::Lorem.paragraph(sentence_count: 5) }
      closed_at { Time.current }
      assigned_investigator factory: %i[user investigator]
    end

    trait :high_priority do
      priority { :high }
    end

    trait :critical do
      priority { :critical }
    end
  end
end
