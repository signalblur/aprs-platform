# frozen_string_literal: true

require "rails_helper"

RSpec.describe EquipmentEffect, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:equipment_effect)).to be_valid
    end

    it "has a valid without_description factory" do
      expect(build(:equipment_effect, :without_description)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:sighting) }
  end

  describe "validations" do
    it { is_expected.to validate_presence_of(:equipment_type) }
    it { is_expected.to validate_presence_of(:effect_type) }
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:sighting_id).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:equipment_type).of_type(:string).with_options(null: false) }
    it { is_expected.to have_db_column(:effect_type).of_type(:string).with_options(null: false) }
    it { is_expected.to have_db_column(:description).of_type(:text) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
    it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(null: false) }
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:sighting_id) }
  end
end
