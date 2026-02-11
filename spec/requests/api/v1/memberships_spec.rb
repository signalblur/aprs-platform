# frozen_string_literal: true

require "rails_helper"

RSpec.describe "API v1 Membership", type: :request do
  let(:user) { create(:user) }
  let(:api_key) { create(:api_key, user: user) }
  let(:headers) { { "X-Api-Key" => api_key.raw_key } }

  describe "GET /api/v1/membership" do
    it "returns 401 without API key" do
      get api_v1_membership_path
      expect(response).to have_http_status(:unauthorized)
    end

    it "returns 200 with valid API key" do
      get api_v1_membership_path, headers: headers
      expect(response).to have_http_status(:ok)
    end

    it "returns JSON content type" do
      get api_v1_membership_path, headers: headers
      expect(response.content_type).to start_with("application/json")
    end

    context "when user has no active membership" do
      it "returns free tier" do
        get api_v1_membership_path, headers: headers
        data = response.parsed_body["data"]
        expect(data["tier"]).to eq("free")
      end

      it "returns inactive status" do
        get api_v1_membership_path, headers: headers
        data = response.parsed_body["data"]
        expect(data["active"]).to be false
      end

      it "returns nil timestamps" do
        get api_v1_membership_path, headers: headers
        data = response.parsed_body["data"]
        expect(data["starts_at"]).to be_nil
        expect(data["expires_at"]).to be_nil
      end

      it "returns free tier limits" do
        get api_v1_membership_path, headers: headers
        limits = response.parsed_body["data"]["limits"]
        expect(limits["sightings_per_month"]).to eq(5)
        expect(limits["evidence_per_sighting"]).to eq(3)
        expect(limits["evidence_max_size_mb"]).to eq(50)
        expect(limits["api_keys"]).to eq(1)
      end
    end

    context "when user has professional membership" do
      before { create(:membership, :professional, user: user) }

      it "returns professional tier" do
        get api_v1_membership_path, headers: headers
        data = response.parsed_body["data"]
        expect(data["tier"]).to eq("professional")
      end

      it "returns active status" do
        get api_v1_membership_path, headers: headers
        data = response.parsed_body["data"]
        expect(data["active"]).to be true
      end

      it "returns ISO 8601 starts_at" do
        get api_v1_membership_path, headers: headers
        starts_at = response.parsed_body["data"]["starts_at"]
        expect { Time.iso8601(starts_at) }.not_to raise_error
      end

      it "returns professional tier limits" do
        get api_v1_membership_path, headers: headers
        limits = response.parsed_body["data"]["limits"]
        expect(limits["sightings_per_month"]).to eq(50)
        expect(limits["evidence_per_sighting"]).to eq(10)
        expect(limits["api_keys"]).to eq(5)
      end
    end

    context "when user has organization membership" do
      before { create(:membership, :organization, user: user) }

      it "returns organization tier" do
        get api_v1_membership_path, headers: headers
        data = response.parsed_body["data"]
        expect(data["tier"]).to eq("organization")
      end

      it "returns nil for unlimited sightings_per_month" do
        get api_v1_membership_path, headers: headers
        limits = response.parsed_body["data"]["limits"]
        expect(limits["sightings_per_month"]).to be_nil
      end
    end

    context "when user has expired membership" do
      before { create(:membership, :professional, user: user, expires_at: 1.day.ago) }

      it "returns free tier" do
        get api_v1_membership_path, headers: headers
        data = response.parsed_body["data"]
        expect(data["tier"]).to eq("free")
      end

      it "returns free tier limits" do
        get api_v1_membership_path, headers: headers
        limits = response.parsed_body["data"]["limits"]
        expect(limits["sightings_per_month"]).to eq(5)
      end
    end
  end
end
