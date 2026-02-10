# frozen_string_literal: true

require "rails_helper"

RSpec.describe SightingsHelper do
  describe "#sightings_to_geojson" do
    let(:shape) { create(:shape) }

    it "returns a valid FeatureCollection" do
      create(:sighting, shape: shape)

      result = helper.sightings_to_geojson(Sighting.includes(:shape).all)
      parsed = JSON.parse(result)

      expect(parsed["type"]).to eq("FeatureCollection")
      expect(parsed["features"]).to be_an(Array)
      expect(parsed["features"].size).to eq(1)
    end

    it "includes correct coordinates from the geography point" do
      create(:sighting, shape: shape, location: "POINT(-104.9903 39.7392)")

      result = helper.sightings_to_geojson(Sighting.includes(:shape).all)
      parsed = JSON.parse(result)
      coords = parsed["features"].first["geometry"]["coordinates"]

      expect(coords[0]).to be_within(0.001).of(-104.9903)
      expect(coords[1]).to be_within(0.001).of(39.7392)
    end

    it "includes shape name and status in feature properties" do
      sighting = create(:sighting, shape: shape)

      result = helper.sightings_to_geojson(Sighting.includes(:shape).all)
      parsed = JSON.parse(result)
      properties = parsed["features"].first["properties"]

      expect(properties["shape"]).to eq(shape.name)
      expect(properties["status"]).to eq("submitted")
      expect(properties["id"]).to eq(sighting.id)
    end

    it "filters out sightings without a location" do
      create(:sighting, shape: shape, location: nil)
      create(:sighting, shape: shape, location: "POINT(-104.9903 39.7392)")

      result = helper.sightings_to_geojson(Sighting.includes(:shape).all)
      parsed = JSON.parse(result)

      expect(parsed["features"].size).to eq(1)
    end

    it "returns an empty FeatureCollection for no sightings" do
      result = helper.sightings_to_geojson(Sighting.none)
      parsed = JSON.parse(result)

      expect(parsed["type"]).to eq("FeatureCollection")
      expect(parsed["features"]).to be_empty
    end

    it "escapes HTML in popup content" do
      create(:sighting, shape: shape, description: '<script>alert("xss")</script>' + "x" * 20)

      result = helper.sightings_to_geojson(Sighting.includes(:shape).all)
      parsed = JSON.parse(result)
      popup = parsed["features"].first["properties"]["popup"]

      expect(popup).not_to include("<script>")
      expect(popup).to include("&lt;script&gt;")
    end

    it "truncates long descriptions in popup content" do
      long_desc = "A" * 200
      create(:sighting, shape: shape, description: long_desc)

      result = helper.sightings_to_geojson(Sighting.includes(:shape).all)
      parsed = JSON.parse(result)
      popup = parsed["features"].first["properties"]["popup"]

      expect(popup).to include("...")
      expect(popup.length).to be < long_desc.length + 200
    end
  end
end
