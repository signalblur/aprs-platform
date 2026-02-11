# frozen_string_literal: true

require "rails_helper"

RSpec.describe Evidence, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:evidence)).to be_valid
    end

    it "has a valid with_file factory" do
      expect(build(:evidence, :with_file)).to be_valid
    end

    it "has a valid video factory" do
      expect(build(:evidence, :video)).to be_valid
    end

    it "has a valid audio factory" do
      expect(build(:evidence, :audio)).to be_valid
    end

    it "has a valid document factory" do
      expect(build(:evidence, :document)).to be_valid
    end

    it "has a valid other factory" do
      expect(build(:evidence, :other)).to be_valid
    end

    it "has a valid with_png factory" do
      expect(build(:evidence, :with_png)).to be_valid
    end

    it "has a valid with_pdf factory" do
      expect(build(:evidence, :with_pdf)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:sighting).optional }
    it { is_expected.to belong_to(:investigation).optional }
    it { is_expected.to belong_to(:submitted_by).class_name("User") }
  end

  describe "evidence_type enum" do
    subject(:evidence) { described_class.new }

    it {
      expect(evidence).to define_enum_for(:evidence_type)
        .with_values(photo: 0, video: 1, audio: 2, document: 3, other: 4)
        .with_default(:photo)
    }

    it "defaults to photo" do
      expect(evidence.evidence_type).to eq("photo")
    end
  end

  describe "file attachment" do
    it "can have an attached file" do
      evidence = build(:evidence, :with_file)
      expect(evidence.file).to be_attached
    end

    it "is valid without an attached file" do
      evidence = build(:evidence)
      expect(evidence.file).not_to be_attached
      expect(evidence).to be_valid
    end
  end

  describe "file validations" do
    context "with allowed content types" do
      it "accepts JPEG images" do
        evidence = build(:evidence, :with_file)
        expect(evidence).to be_valid
      end

      it "accepts PNG images" do
        evidence = build(:evidence, :with_png)
        expect(evidence).to be_valid
      end

      it "accepts PDF documents" do
        evidence = build(:evidence, :with_pdf)
        expect(evidence).to be_valid
      end
    end

    context "with disallowed content types" do
      it "rejects executable files" do
        evidence = build(:evidence)
        evidence.file.attach(
          io: StringIO.new("MZ" + "\x00" * 100),
          filename: "malware.exe",
          content_type: "application/x-msdownload"
        )
        expect(evidence).not_to be_valid
        expect(evidence.errors[:file]).to include("has an unsupported content type")
      end

      it "rejects HTML files" do
        evidence = build(:evidence)
        evidence.file.attach(
          io: StringIO.new("<html></html>"),
          filename: "page.html",
          content_type: "text/html"
        )
        expect(evidence).not_to be_valid
        expect(evidence.errors[:file]).to include("has an unsupported content type")
      end
    end

    context "with magic byte verification" do
      it "rejects files with mismatched content type and magic bytes" do
        evidence = build(:evidence)
        evidence.file.attach(
          io: StringIO.new("This is plain text, not a JPEG"),
          filename: "fake.jpg",
          content_type: "image/jpeg"
        )
        expect(evidence).not_to be_valid
        expect(evidence.errors[:file]).to include("content does not match its declared type")
      end

      it "accepts files with matching magic bytes" do
        evidence = build(:evidence, :with_file)
        expect(evidence).to be_valid
      end

      it "skips magic byte check gracefully when file header is unreadable" do
        evidence = build(:evidence)
        evidence.file.attach(
          io: StringIO.new("\xFF\xD8\xFF\xE0" + "\x00" * 100),
          filename: "test.jpg",
          content_type: "image/jpeg"
        )
        change = evidence.attachment_changes["file"]
        allow(change).to receive(:attachable).and_raise(StandardError, "IO error")
        expect(evidence).to be_valid
      end

      it "returns nil from header read when no attachment change is present" do
        evidence = build(:evidence)
        evidence.file.attach(
          io: StringIO.new("\xFF\xD8\xFF\xE0" + "\x00" * 100),
          filename: "test.jpg",
          content_type: "image/jpeg"
        )
        # Clear attachment_changes to simulate missing change entry
        evidence.attachment_changes.clear
        expect(evidence.send(:read_header_from_attachment_change)).to be_nil
      end

      it "skips magic byte check when attachable is not a Hash" do
        evidence = build(:evidence)
        evidence.file.attach(
          io: StringIO.new("\xFF\xD8\xFF\xE0" + "\x00" * 100),
          filename: "test.jpg",
          content_type: "image/jpeg"
        )
        change = evidence.attachment_changes["file"]
        allow(change).to receive(:attachable).and_return(ActiveStorage::Blob.new)
        expect(evidence).to be_valid
      end
    end

    context "with file size limits" do
      it "rejects files over 100 MB" do
        evidence = build(:evidence)
        blob = ActiveStorage::Blob.create_and_upload!(
          io: StringIO.new("\xFF\xD8\xFF\xE0" + "\x00" * 10),
          filename: "large.jpg",
          content_type: "image/jpeg"
        )
        # Stub byte_size to simulate a large file
        allow(blob).to receive(:byte_size).and_return(101.megabytes)
        evidence.file.attach(blob)
        expect(evidence).not_to be_valid
        expect(evidence.errors[:file]).to include("is too large (maximum is 100 MB)")
      end
    end
  end

  describe "XOR parent validation" do
    it "is valid with sighting and no investigation" do
      expect(build(:evidence)).to be_valid
    end

    it "is valid with investigation and no sighting" do
      expect(build(:evidence, :for_investigation)).to be_valid
    end

    it "is invalid with both sighting and investigation" do
      evidence = build(:evidence, investigation: build(:investigation))
      expect(evidence).not_to be_valid
      expect(evidence.errors[:base]).to include("must belong to either a sighting or an investigation, not both")
    end

    it "is invalid with neither sighting nor investigation" do
      evidence = build(:evidence, sighting: nil, investigation: nil)
      expect(evidence).not_to be_valid
      expect(evidence.errors[:base]).to include("must belong to either a sighting or an investigation")
    end
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:sighting_id).of_type(:integer) }
    it { is_expected.to have_db_column(:investigation_id).of_type(:integer) }
    it { is_expected.to have_db_column(:submitted_by_id).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:evidence_type).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:description).of_type(:text) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
    it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(null: false) }
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:sighting_id) }
    it { is_expected.to have_db_index(:investigation_id) }
    it { is_expected.to have_db_index(:submitted_by_id) }
  end
end
