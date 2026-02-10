# frozen_string_literal: true

require "swagger_helper"

RSpec.describe "API v1 Shapes" do
  path "/api/v1/shapes" do
    get "Lists all UAP shape categories" do
      tags "Shapes"
      produces "application/json"
      security [api_key: []]

      response "200", "shapes retrieved" do
        schema type: :object,
               properties: {
                 data: { type: :array, items: { "$ref": "#/components/schemas/Shape" } }
               },
               required: %w[data]

        let(:user) { create(:user) }
        let(:api_key) { create(:api_key, user: user) }
        let(:"X-Api-Key") { api_key.raw_key }

        before { create(:shape, name: "Disc", description: "Flat disc-shaped object") }

        run_test! do |response|
          data = JSON.parse(response.body)
          expect(data["data"]).to be_an(Array)
          expect(data["data"].first).to include("id", "name", "description")
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
