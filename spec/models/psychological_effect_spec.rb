# frozen_string_literal: true

require "rails_helper"

RSpec.describe PsychologicalEffect, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:psychological_effect)).to be_valid
    end

    it "has a valid without_optional_fields factory" do
      expect(build(:psychological_effect, :without_optional_fields)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:sighting) }
  end

  describe "validations" do
    it { is_expected.to validate_presence_of(:effect_type) }
  end

  describe "severity enum" do
    subject(:effect) { described_class.new }

    it {
      expect(effect).to define_enum_for(:severity)
        .with_values(mild: 0, moderate: 1, severe: 2)
        .with_default(:mild)
    }

    it "defaults to mild" do
      expect(effect.severity).to eq("mild")
    end
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:sighting_id).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:effect_type).of_type(:string).with_options(null: false) }
    it { is_expected.to have_db_column(:description).of_type(:text) }
    it { is_expected.to have_db_column(:severity).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:onset).of_type(:string) }
    it { is_expected.to have_db_column(:duration).of_type(:string) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
    it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(null: false) }
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:sighting_id) }
  end
end
