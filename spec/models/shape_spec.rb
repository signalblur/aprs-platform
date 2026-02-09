# frozen_string_literal: true

require "rails_helper"

RSpec.describe Shape, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:shape)).to be_valid
    end

    it "has a valid factory without description" do
      expect(build(:shape, :without_description)).to be_valid
    end
  end

  describe "validations" do
    subject { build(:shape) }

    it { is_expected.to validate_presence_of(:name) }
    it { is_expected.to validate_uniqueness_of(:name) }
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:name).of_type(:string).with_options(null: false) }
    it { is_expected.to have_db_column(:description).of_type(:text) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:name).unique(true) }
  end
end
