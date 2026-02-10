# frozen_string_literal: true

require "rails_helper"

RSpec.describe "API v1 Shapes", type: :request do
  let(:user) { create(:user) }
  let(:api_key) { create(:api_key, user: user) }
  let(:headers) { { "X-Api-Key" => api_key.raw_key } }

  describe "GET /api/v1/shapes" do
    it "returns 401 without API key" do
      get api_v1_shapes_path
      expect(response).to have_http_status(:unauthorized)
    end

    it "returns 200 with valid API key" do
      get api_v1_shapes_path, headers: headers
      expect(response).to have_http_status(:ok)
    end

    it "returns JSON content type" do
      get api_v1_shapes_path, headers: headers
      expect(response.content_type).to start_with("application/json")
    end

    it "returns data array" do
      get api_v1_shapes_path, headers: headers
      expect(response.parsed_body["data"]).to be_an(Array)
    end

    it "returns empty array when no shapes exist" do
      get api_v1_shapes_path, headers: headers
      expect(response.parsed_body["data"]).to eq([])
    end

    context "with shapes" do
      before do
        create(:shape, name: "Disc")
        create(:shape, name: "Triangle")
      end

      it "returns all shapes" do
        get api_v1_shapes_path, headers: headers
        expect(response.parsed_body["data"].length).to eq(2)
      end

      it "orders shapes by name" do
        get api_v1_shapes_path, headers: headers
        names = response.parsed_body["data"].map { |s| s["name"] }
        expect(names).to eq(%w[Disc Triangle])
      end

      it "serializes shape fields" do
        get api_v1_shapes_path, headers: headers
        first = response.parsed_body["data"].first
        expect(first).to include("id", "name", "description")
      end
    end
  end
end
