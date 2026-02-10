# frozen_string_literal: true

require "rails_helper"

RSpec.describe EnvironmentalTrace, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:environmental_trace)).to be_valid
    end

    it "has a valid with_location factory" do
      expect(build(:environmental_trace, :with_location)).to be_valid
    end

    it "has a valid with_measurement factory" do
      expect(build(:environmental_trace, :with_measurement)).to be_valid
    end

    it "has a valid without_optional_fields factory" do
      expect(build(:environmental_trace, :without_optional_fields)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:sighting) }
  end

  describe "validations" do
    it { is_expected.to validate_presence_of(:trace_type) }

    it "is invalid when measured_value is present without measurement_unit" do
      trace = build(:environmental_trace, measured_value: "2.5", measurement_unit: nil)
      expect(trace).not_to be_valid
      expect(trace.errors[:measurement_unit]).to include("can't be blank")
    end

    it "is valid when both measured_value and measurement_unit are present" do
      trace = build(:environmental_trace, :with_measurement)
      expect(trace).to be_valid
    end

    it "is valid when neither measured_value nor measurement_unit are present" do
      trace = build(:environmental_trace, measured_value: nil, measurement_unit: nil)
      expect(trace).to be_valid
    end
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:sighting_id).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:trace_type).of_type(:string).with_options(null: false) }
    it { is_expected.to have_db_column(:description).of_type(:text) }
    it { is_expected.to have_db_column(:measured_value).of_type(:string) }
    it { is_expected.to have_db_column(:measurement_unit).of_type(:string) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
    it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(null: false) }

    it "stores location as PostGIS geography point" do
      column = described_class.columns_hash["location"]
      expect(column.sql_type).to include("geography")
    end
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:sighting_id) }

    it "has a GiST spatial index on location" do
      indexes = ActiveRecord::Base.connection.indexes(:environmental_traces)
      gist_index = indexes.find { |idx| idx.columns.include?("location") }
      expect(gist_index).to be_present
      expect(gist_index.using).to eq(:gist)
    end
  end
end
