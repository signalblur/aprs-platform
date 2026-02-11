# frozen_string_literal: true

require "rails_helper"

RSpec.describe InvestigationNote, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:investigation_note)).to be_valid
    end

    it "has a valid status_change factory" do
      expect(build(:investigation_note, :status_change)).to be_valid
    end

    it "has a valid assignment factory" do
      expect(build(:investigation_note, :assignment)).to be_valid
    end

    it "has a valid finding factory" do
      expect(build(:investigation_note, :finding)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:investigation) }
    it { is_expected.to belong_to(:author).class_name("User") }
  end

  describe "validations" do
    subject(:note) { build(:investigation_note) }

    it { is_expected.to validate_presence_of(:content) }

    it {
      expect(note).to validate_length_of(:content)
        .is_at_least(1)
        .is_at_most(10_000)
    }
  end

  describe "note_type enum" do
    subject(:note) { described_class.new }

    it {
      expect(note).to define_enum_for(:note_type)
        .with_values(general: 0, status_change: 1, assignment: 2, finding: 3)
        .with_default(:general)
    }

    it "defaults to general" do
      expect(note.note_type).to eq("general")
    end
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:investigation_id).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:author_id).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:content).of_type(:text).with_options(null: false) }
    it { is_expected.to have_db_column(:note_type).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
    it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(null: false) }
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:investigation_id) }
    it { is_expected.to have_db_index(:author_id) }
  end
end
