# frozen_string_literal: true

require "swagger_helper"

RSpec.describe "API v1 Membership" do
  let(:user) { create(:user) }
  let(:api_key) { create(:api_key, user: user) }

  path "/api/v1/membership" do
    get "Returns the current user's membership tier and limits" do
      tags "Membership"
      produces "application/json"
      security [api_key: []]

      response "200", "free tier (no active membership)" do
        schema type: :object,
               properties: {
                 data: { "$ref": "#/components/schemas/Membership" }
               },
               required: %w[data]

        let(:"X-Api-Key") { api_key.raw_key }

        run_test! do |response|
          data = JSON.parse(response.body)["data"]
          expect(data["tier"]).to eq("free")
          expect(data["active"]).to be false
          expect(data["limits"]).to include("sightings_per_month", "evidence_per_sighting")
        end
      end

      response "200", "professional tier (active membership)" do
        schema type: :object,
               properties: {
                 data: { "$ref": "#/components/schemas/Membership" }
               },
               required: %w[data]

        let(:user) { create(:user) }
        let(:api_key) { create(:api_key, user: user) }
        let(:"X-Api-Key") { api_key.raw_key }

        before { create(:membership, :professional, user: user) }

        run_test! do |response|
          data = JSON.parse(response.body)["data"]
          expect(data["tier"]).to eq("professional")
          expect(data["active"]).to be true
          expect(data["limits"]["sightings_per_month"]).to eq(50)
        end
      end

      response "401", "unauthorized — missing or invalid API key" do
        schema "$ref": "#/components/schemas/ErrorResponse"

        let(:"X-Api-Key") { "invalid-key" }

        run_test! do |response|
          data = JSON.parse(response.body)
          expect(data["error"]).to eq("Unauthorized")
        end
      end
    end
  end
end
