# frozen_string_literal: true

FactoryBot.define do
  factory :evidence do
    sighting
    submitted_by factory: :user
    evidence_type { :photo }
    description { Faker::Lorem.paragraph }

    trait :video do
      evidence_type { :video }
    end

    trait :audio do
      evidence_type { :audio }
    end

    trait :document do
      evidence_type { :document }
    end

    trait :other do
      evidence_type { :other }
    end

    trait :with_file do
      after(:build) do |evidence|
        evidence.file.attach(
          io: StringIO.new("\xFF\xD8\xFF\xE0" + "\x00" * 100),
          filename: "test_photo.jpg",
          content_type: "image/jpeg"
        )
      end
    end

    trait :with_png do
      after(:build) do |evidence|
        evidence.file.attach(
          io: StringIO.new("\x89PNG\r\n\x1A\n" + "\x00" * 100),
          filename: "test_photo.png",
          content_type: "image/png"
        )
      end
    end

    trait :with_pdf do
      evidence_type { :document }

      after(:build) do |evidence|
        evidence.file.attach(
          io: StringIO.new("%PDF-1.4" + "\x00" * 100),
          filename: "test_document.pdf",
          content_type: "application/pdf"
        )
      end
    end
  end
end
