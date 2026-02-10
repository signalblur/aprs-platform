# frozen_string_literal: true

require "rails_helper"

RSpec.describe Api::V1::SightingSerializer do
  subject(:json) { described_class.new(sighting).as_json }

  let(:user) { create(:user) }
  let(:shape) { create(:shape) }
  let(:sighting) { create(:sighting, submitter: user, shape: shape) }

  it "includes id" do
    expect(json[:id]).to eq(sighting.id)
  end

  it "includes description" do
    expect(json[:description]).to eq(sighting.description)
  end

  it "includes status" do
    expect(json[:status]).to eq(sighting.status)
  end

  it "includes shape as hash with id and name" do
    expect(json[:shape]).to eq({ id: shape.id, name: shape.name })
  end

  it "excludes submitter_email to prevent PII leakage" do
    expect(json).not_to have_key(:submitter_email)
  end

  it "includes location as lat/lng hash" do
    expect(json[:location]).to eq({
      lat: sighting.location.latitude,
      lng: sighting.location.longitude
    })
  end

  it "includes altitude_feet as float" do
    sighting_with_alt = create(:sighting, altitude_feet: 5000)
    result = described_class.new(sighting_with_alt).as_json
    expect(result[:altitude_feet]).to eq(5000.0)
  end

  it "includes duration_seconds" do
    expect(json[:duration_seconds]).to eq(sighting.duration_seconds)
  end

  it "includes num_witnesses" do
    expect(json[:num_witnesses]).to eq(sighting.num_witnesses)
  end

  it "includes visibility_conditions" do
    expect(json[:visibility_conditions]).to eq(sighting.visibility_conditions)
  end

  it "includes weather_notes" do
    expect(json[:weather_notes]).to eq(sighting.weather_notes)
  end

  it "includes media_source" do
    expect(json[:media_source]).to eq(sighting.media_source)
  end

  it "includes observed_at as ISO 8601" do
    expect(json[:observed_at]).to eq(sighting.observed_at.iso8601)
  end

  it "includes observed_timezone" do
    expect(json[:observed_timezone]).to eq(sighting.observed_timezone)
  end

  it "includes created_at as ISO 8601" do
    expect(json[:created_at]).to eq(sighting.created_at.iso8601)
  end

  it "includes updated_at as ISO 8601" do
    expect(json[:updated_at]).to eq(sighting.updated_at.iso8601)
  end

  context "when location is nil" do
    let(:sighting) { create(:sighting, submitter: user, shape: shape, location: nil) }

    it "returns nil for location" do
      expect(json[:location]).to be_nil
    end
  end

  context "when altitude_feet is nil" do
    let(:sighting) { create(:sighting, submitter: user, shape: shape, altitude_feet: nil) }

    it "returns nil for altitude_feet" do
      expect(json[:altitude_feet]).to be_nil
    end
  end
end
