# frozen_string_literal: true

FactoryBot.define do
  factory :investigation_note do
    investigation
    author factory: %i[user investigator]
    content { Faker::Lorem.paragraph(sentence_count: 3) }
    note_type { :general }

    trait :status_change do
      note_type { :status_change }
    end

    trait :assignment do
      note_type { :assignment }
    end

    trait :finding do
      note_type { :finding }
    end
  end
end
