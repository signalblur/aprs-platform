# frozen_string_literal: true

require "rails_helper"

RSpec.describe Sighting, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:sighting)).to be_valid
    end

    it "has a valid anonymous factory" do
      expect(build(:sighting, :anonymous)).to be_valid
    end

    it "has a valid under_review factory" do
      expect(build(:sighting, :under_review)).to be_valid
    end

    it "has a valid verified factory" do
      expect(build(:sighting, :verified)).to be_valid
    end

    it "has a valid rejected factory" do
      expect(build(:sighting, :rejected)).to be_valid
    end

    it "has a valid without_optional_fields factory" do
      expect(build(:sighting, :without_optional_fields)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:submitter).class_name("User").optional }
    it { is_expected.to belong_to(:shape) }
    it { is_expected.to have_many(:physiological_effects).dependent(:destroy) }
    it { is_expected.to have_many(:psychological_effects).dependent(:destroy) }
    it { is_expected.to have_many(:equipment_effects).dependent(:destroy) }
    it { is_expected.to have_many(:environmental_traces).dependent(:destroy) }
    it { is_expected.to have_many(:evidences).dependent(:destroy) }
    it { is_expected.to have_many(:witnesses).dependent(:destroy) }
  end

  describe "validations" do
    subject(:sighting) { build(:sighting) }

    it { is_expected.to validate_presence_of(:description) }

    it {
      expect(sighting).to validate_length_of(:description)
        .is_at_least(20)
        .is_at_most(10_000)
    }

    it { is_expected.to validate_presence_of(:observed_at) }
    it { is_expected.to validate_presence_of(:observed_timezone) }

    it {
      expect(sighting).to validate_inclusion_of(:observed_timezone)
        .in_array(ActiveSupport::TimeZone::MAPPING.values)
    }

    it {
      expect(sighting).to validate_numericality_of(:num_witnesses)
        .is_greater_than_or_equal_to(1)
        .only_integer
    }

    it {
      expect(sighting).to validate_numericality_of(:duration_seconds)
        .is_greater_than(0)
        .only_integer
        .allow_nil
    }
  end

  describe "status enum" do
    subject(:sighting) { described_class.new }

    it {
      expect(sighting).to define_enum_for(:status)
        .with_values(submitted: 0, under_review: 1, verified: 2, rejected: 3)
        .with_default(:submitted)
    }

    it "defaults to submitted" do
      expect(sighting.status).to eq("submitted")
    end
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:submitter_id).of_type(:integer) }
    it { is_expected.to have_db_column(:shape_id).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:description).of_type(:text).with_options(null: false) }
    it { is_expected.to have_db_column(:duration_seconds).of_type(:integer) }
    it { is_expected.to have_db_column(:altitude_feet).of_type(:decimal) }
    it { is_expected.to have_db_column(:observed_timezone).of_type(:string).with_options(null: false) }
    it { is_expected.to have_db_column(:num_witnesses).of_type(:integer).with_options(null: false, default: 1) }
    it { is_expected.to have_db_column(:visibility_conditions).of_type(:string) }
    it { is_expected.to have_db_column(:weather_notes).of_type(:text) }
    it { is_expected.to have_db_column(:media_source).of_type(:string) }
    it { is_expected.to have_db_column(:status).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
    it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(null: false) }

    it "stores observed_at as timestamptz" do
      column = described_class.columns_hash["observed_at"]
      expect(column.sql_type).to eq("timestamp with time zone")
    end

    it "stores location as PostGIS geography point" do
      column = described_class.columns_hash["location"]
      expect(column.sql_type).to include("geography")
    end
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:submitter_id) }
    it { is_expected.to have_db_index(:shape_id) }
    it { is_expected.to have_db_index(:observed_at) }
    it { is_expected.to have_db_index(:status) }

    it "has a GiST spatial index on location" do
      indexes = ActiveRecord::Base.connection.indexes(:sightings)
      gist_index = indexes.find { |idx| idx.columns.include?("location") }
      expect(gist_index).to be_present
      expect(gist_index.using).to eq(:gist)
    end
  end

  describe "scopes" do
    describe ".recent" do
      it "orders by observed_at descending" do
        old_sighting = create(:sighting, observed_at: 3.days.ago)
        new_sighting = create(:sighting, observed_at: 1.hour.ago)

        expect(described_class.recent).to eq([ new_sighting, old_sighting ])
      end
    end

    describe ".by_status" do
      it "filters sightings by status" do
        submitted = create(:sighting)
        create(:sighting, :under_review)

        expect(described_class.by_status(:submitted)).to eq([ submitted ])
      end
    end

    describe ".by_shape" do
      it "filters sightings by shape_id" do
        shape = create(:shape)
        matching = create(:sighting, shape: shape)
        create(:sighting)

        expect(described_class.by_shape(shape.id)).to eq([ matching ])
      end
    end

    describe ".observed_between" do
      it "filters sightings within a date range" do
        inside = create(:sighting, observed_at: 5.days.ago)
        create(:sighting, observed_at: 30.days.ago)

        expect(described_class.observed_between(7.days.ago, Time.current)).to eq([ inside ])
      end
    end

    describe ".search_description" do
      it "matches case-insensitively" do
        sighting = create(:sighting, description: "A bright light hovered above the treeline at night")
        create(:sighting, description: "A loud rumbling sound came from the ground below")

        expect(described_class.search_description("bright")).to eq([ sighting ])
      end

      it "returns empty when no match" do
        create(:sighting, description: "A bright light hovered above the treeline at night")

        expect(described_class.search_description("submarine")).to be_empty
      end

      it "escapes SQL wildcard characters" do
        sighting = create(:sighting, description: "Object moved at 100% speed then stopped")
        create(:sighting, description: "Object moved at full speed then stopped here")

        expect(described_class.search_description("100%")).to eq([ sighting ])
      end
    end

    describe ".within_radius" do
      let(:denver_lat) { 39.7392 }
      let(:denver_lng) { -104.9903 }

      it "includes sightings within the radius" do
        boulder = create(:sighting, :in_boulder)

        results = described_class.within_radius(denver_lat, denver_lng, 50_000)
        expect(results).to include(boulder)
      end

      it "excludes sightings outside the radius" do
        nyc = create(:sighting, :in_nyc)

        results = described_class.within_radius(denver_lat, denver_lng, 50_000)
        expect(results).not_to include(nyc)
      end
    end
  end
end
