# frozen_string_literal: true

require "rails_helper"

RSpec.describe "API v1 Sightings", type: :request do
  let(:user) { create(:user) }
  let(:api_key) { create(:api_key, user: user) }
  let(:headers) { { "X-Api-Key" => api_key.raw_key } }
  let(:shape) { create(:shape) }

  describe "GET /api/v1/sightings" do
    it "returns 401 without API key" do
      get api_v1_sightings_path
      expect(response).to have_http_status(:unauthorized)
    end

    it "returns 200 with valid API key" do
      get api_v1_sightings_path, headers: headers
      expect(response).to have_http_status(:ok)
    end

    it "returns JSON content type" do
      get api_v1_sightings_path, headers: headers
      expect(response.content_type).to start_with("application/json")
    end

    context "with sightings" do
      let!(:sighting) { create(:sighting, submitter: user, shape: shape) }

      it "returns data array" do
        get api_v1_sightings_path, headers: headers
        expect(response.parsed_body["data"]).to be_an(Array)
      end

      it "returns meta with pagination" do
        get api_v1_sightings_path, headers: headers
        meta = response.parsed_body["meta"]
        expect(meta).to include("page", "per_page", "total", "total_pages")
      end

      it "includes sighting id" do
        get api_v1_sightings_path, headers: headers
        expect(response.parsed_body["data"].first["id"]).to eq(sighting.id)
      end

      it "includes description" do
        get api_v1_sightings_path, headers: headers
        expect(response.parsed_body["data"].first["description"]).to eq(sighting.description)
      end

      it "includes status" do
        get api_v1_sightings_path, headers: headers
        expect(response.parsed_body["data"].first["status"]).to eq("submitted")
      end

      it "includes shape as hash" do
        get api_v1_sightings_path, headers: headers
        shape_data = response.parsed_body["data"].first["shape"]
        expect(shape_data).to eq({ "id" => shape.id, "name" => shape.name })
      end

      it "excludes submitter_email from response" do
        get api_v1_sightings_path, headers: headers
        expect(response.parsed_body["data"].first).not_to have_key("submitter_email")
      end

      it "includes location as lat/lng hash" do
        get api_v1_sightings_path, headers: headers
        location = response.parsed_body["data"].first["location"]
        expect(location).to include("lat", "lng")
      end

      it "includes ISO 8601 observed_at" do
        get api_v1_sightings_path, headers: headers
        observed_at = response.parsed_body["data"].first["observed_at"]
        expect { Time.iso8601(observed_at) }.not_to raise_error
      end

      it "includes ISO 8601 created_at" do
        get api_v1_sightings_path, headers: headers
        created_at = response.parsed_body["data"].first["created_at"]
        expect { Time.iso8601(created_at) }.not_to raise_error
      end

      it "includes ISO 8601 updated_at" do
        get api_v1_sightings_path, headers: headers
        updated_at = response.parsed_body["data"].first["updated_at"]
        expect { Time.iso8601(updated_at) }.not_to raise_error
      end
    end

    context "when sighting has nil location" do
      before { create(:sighting, shape: shape, location: nil) }

      it "returns nil for location" do
        get api_v1_sightings_path, headers: headers
        expect(response.parsed_body["data"].first["location"]).to be_nil
      end
    end

    describe "pagination" do
      before { create_list(:sighting, 25, shape: shape) }

      it "defaults to 20 per page" do
        get api_v1_sightings_path, headers: headers
        expect(response.parsed_body["data"].length).to eq(20)
      end

      it "returns correct meta for first page" do
        get api_v1_sightings_path, headers: headers
        meta = response.parsed_body["meta"]
        expect(meta["page"]).to eq(1)
        expect(meta["per_page"]).to eq(20)
        expect(meta["total"]).to eq(25)
        expect(meta["total_pages"]).to eq(2)
      end

      it "supports page param" do
        get api_v1_sightings_path, params: { page: 2 }, headers: headers
        expect(response.parsed_body["data"].length).to eq(5)
        expect(response.parsed_body["meta"]["page"]).to eq(2)
      end

      it "handles overflow page gracefully" do
        get api_v1_sightings_path, params: { page: 999 }, headers: headers
        expect(response).to have_http_status(:not_found)
      end
    end

    describe "ordering" do
      it "returns most recent sightings first" do
        old = create(:sighting, shape: shape, observed_at: 2.days.ago)
        recent = create(:sighting, shape: shape, observed_at: 1.hour.ago)
        get api_v1_sightings_path, headers: headers
        ids = response.parsed_body["data"].map { |s| s["id"] }
        expect(ids).to eq([ recent.id, old.id ])
      end
    end

    describe "filters" do
      it "filters by status" do
        create(:sighting, :verified, shape: shape)
        create(:sighting, shape: shape)
        get api_v1_sightings_path, params: { status: "verified" }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
        expect(response.parsed_body["data"].first["status"]).to eq("verified")
      end

      it "filters by shape_id" do
        other_shape = create(:shape)
        create(:sighting, shape: shape)
        create(:sighting, shape: other_shape)
        get api_v1_sightings_path, params: { shape_id: shape.id }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
      end

      it "filters by text search" do
        create(:sighting, shape: shape, description: "A bright glowing orb appeared in the sky above Denver")
        create(:sighting, shape: shape, description: "A dark triangular craft hovered silently over the field")
        get api_v1_sightings_path, params: { q: "orb" }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
      end

      it "filters by date range" do
        create(:sighting, shape: shape, observed_at: 5.days.ago)
        create(:sighting, shape: shape, observed_at: 1.day.ago)
        get api_v1_sightings_path, params: {
          date_from: 2.days.ago.to_date.to_s,
          date_to: Date.current.to_s
        }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
      end

      it "filters by location radius" do
        create(:sighting, shape: shape, location: "POINT(-104.9903 39.7392)")  # Denver
        create(:sighting, shape: shape, location: "POINT(-74.0060 40.7128)")   # NYC
        get api_v1_sightings_path, params: {
          lat: 39.7392, lng: -104.9903, radius: 10_000
        }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
      end

      it "combines multiple filters" do
        create(:sighting, :verified, shape: shape, description: "A strange luminous triangle appeared over the mountains")
        create(:sighting, shape: shape, description: "A luminous sphere was seen floating over the neighborhood")
        get api_v1_sightings_path, params: {
          status: "verified", q: "triangle"
        }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
      end

      it "ignores blank filter params" do
        create(:sighting, shape: shape)
        get api_v1_sightings_path, params: {
          status: "", shape_id: "", q: ""
        }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
      end
    end
  end

  describe "GET /api/v1/sightings/:id" do
    let!(:sighting) { create(:sighting, submitter: user, shape: shape) }

    it "returns 401 without API key" do
      get api_v1_sighting_path(sighting)
      expect(response).to have_http_status(:unauthorized)
    end

    it "returns 200 with valid API key" do
      get api_v1_sighting_path(sighting), headers: headers
      expect(response).to have_http_status(:ok)
    end

    it "returns 404 for non-existent sighting" do
      get api_v1_sighting_path(id: 999_999), headers: headers
      expect(response).to have_http_status(:not_found)
    end

    it "returns JSON content type" do
      get api_v1_sighting_path(sighting), headers: headers
      expect(response.content_type).to start_with("application/json")
    end

    it "returns data object with sighting details" do
      get api_v1_sighting_path(sighting), headers: headers
      data = response.parsed_body["data"]
      expect(data["id"]).to eq(sighting.id)
      expect(data["description"]).to eq(sighting.description)
    end

    it "includes association arrays" do
      get api_v1_sighting_path(sighting), headers: headers
      data = response.parsed_body["data"]
      %w[physiological_effects psychological_effects equipment_effects
         environmental_traces evidences witnesses].each do |assoc|
        expect(data).to have_key(assoc)
        expect(data[assoc]).to be_an(Array)
      end
    end

    it "serializes physiological effects" do
      effect = create(:physiological_effect, sighting: sighting)
      get api_v1_sighting_path(sighting), headers: headers
      effects = response.parsed_body["data"]["physiological_effects"]
      expect(effects.length).to eq(1)
      expect(effects.first["id"]).to eq(effect.id)
    end

    it "serializes psychological effects" do
      effect = create(:psychological_effect, sighting: sighting)
      get api_v1_sighting_path(sighting), headers: headers
      effects = response.parsed_body["data"]["psychological_effects"]
      expect(effects.length).to eq(1)
      expect(effects.first["id"]).to eq(effect.id)
    end

    it "serializes equipment effects" do
      effect = create(:equipment_effect, sighting: sighting)
      get api_v1_sighting_path(sighting), headers: headers
      effects = response.parsed_body["data"]["equipment_effects"]
      expect(effects.length).to eq(1)
      expect(effects.first["id"]).to eq(effect.id)
    end

    it "serializes environmental traces with location" do
      create(:environmental_trace, :with_location, sighting: sighting)
      get api_v1_sighting_path(sighting), headers: headers
      traces = response.parsed_body["data"]["environmental_traces"]
      expect(traces.length).to eq(1)
      expect(traces.first["location"]).to include("lat", "lng")
    end

    it "serializes evidences" do
      evidence = create(:evidence, sighting: sighting, submitted_by: user)
      get api_v1_sighting_path(sighting), headers: headers
      evs = response.parsed_body["data"]["evidences"]
      expect(evs.length).to eq(1)
      expect(evs.first["id"]).to eq(evidence.id)
    end

    it "serializes witnesses" do
      witness = create(:witness, :with_statement, sighting: sighting)
      get api_v1_sighting_path(sighting), headers: headers
      witnesses = response.parsed_body["data"]["witnesses"]
      expect(witnesses.length).to eq(1)
      expect(witnesses.first["name"]).to eq(witness.name)
    end

    describe "witness PII gating" do
      before { create(:witness, sighting: sighting) }

      context "when user is a member" do
        it "hides contact_info" do
          get api_v1_sighting_path(sighting), headers: headers
          witness_data = response.parsed_body["data"]["witnesses"].first
          expect(witness_data).not_to have_key("contact_info")
        end
      end

      context "when user is an investigator" do
        let(:user) { create(:user, :investigator) }

        it "shows contact_info" do
          get api_v1_sighting_path(sighting), headers: headers
          witness_data = response.parsed_body["data"]["witnesses"].first
          expect(witness_data).to have_key("contact_info")
        end
      end

      context "when user is an admin" do
        let(:user) { create(:user, :admin) }

        it "shows contact_info" do
          get api_v1_sighting_path(sighting), headers: headers
          witness_data = response.parsed_body["data"]["witnesses"].first
          expect(witness_data).to have_key("contact_info")
        end
      end
    end

    context "with anonymous witness" do
      before { create(:witness, :anonymous, sighting: sighting) }

      it "returns nil for witness name" do
        get api_v1_sighting_path(sighting), headers: headers
        witness_data = response.parsed_body["data"]["witnesses"].first
        expect(witness_data["name"]).to be_nil
      end
    end
  end
end
