# frozen_string_literal: true

require "swagger_helper"

RSpec.describe "API v1 Sightings" do
  let(:user) { create(:user) }
  let(:api_key) { create(:api_key, user: user) }
  let(:shape) { create(:shape) }

  path "/api/v1/sightings" do
    get "Lists sightings with optional filters" do
      tags "Sightings"
      produces "application/json"
      security [api_key: []]

      parameter name: :status, in: :query, type: :string, required: false,
                enum: %w[submitted under_review verified rejected],
                description: "Filter by sighting status"
      parameter name: :shape_id, in: :query, type: :integer, required: false,
                description: "Filter by shape ID"
      parameter name: :q, in: :query, type: :string, required: false,
                description: "Full-text search on description (case-insensitive)"
      parameter name: :date_from, in: :query, type: :string, format: :date, required: false,
                description: "Filter sightings observed on or after this date (YYYY-MM-DD)"
      parameter name: :date_to, in: :query, type: :string, format: :date, required: false,
                description: "Filter sightings observed on or before this date (YYYY-MM-DD)"
      parameter name: :lat, in: :query, type: :number, format: :double, required: false,
                description: "Latitude for radius search (requires lng and radius)"
      parameter name: :lng, in: :query, type: :number, format: :double, required: false,
                description: "Longitude for radius search (requires lat and radius)"
      parameter name: :radius, in: :query, type: :number, required: false,
                description: "Search radius in meters (requires lat and lng)"
      parameter name: :page, in: :query, type: :integer, required: false,
                description: "Page number (default: 1)"

      response "200", "paginated sightings list" do
        schema type: :object,
               properties: {
                 data: { type: :array, items: { "$ref": "#/components/schemas/SightingSummary" } },
                 meta: { "$ref": "#/components/schemas/PaginationMeta" }
               },
               required: %w[data meta]

        let(:"X-Api-Key") { api_key.raw_key }

        before { create(:sighting, submitter: user, shape: shape) }

        run_test! do |response|
          data = JSON.parse(response.body)
          expect(data["data"]).to be_an(Array)
          expect(data["meta"]).to include("page", "per_page", "total", "total_pages")
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

  path "/api/v1/sightings/{id}" do
    get "Retrieves a single sighting with all associations" do
      tags "Sightings"
      produces "application/json"
      security [api_key: []]

      parameter name: :id, in: :path, type: :integer, required: true,
                description: "Sighting ID"

      response "200", "sighting detail (member view — no witness contact_info)" do
        schema type: :object,
               properties: {
                 data: { "$ref": "#/components/schemas/SightingDetail" }
               },
               required: %w[data]

        let(:sighting) { create(:sighting, submitter: user, shape: shape) }
        let(:id) { sighting.id }
        let(:"X-Api-Key") { api_key.raw_key }

        before { create(:witness, :with_statement, sighting: sighting) }

        run_test! do |response|
          data = JSON.parse(response.body)["data"]
          expect(data["id"]).to eq(sighting.id)
          expect(data["witnesses"].first).not_to have_key("contact_info")
        end
      end

      response "200", "sighting detail (investigator view — includes witness contact_info)" do
        schema type: :object,
               properties: {
                 data: { "$ref": "#/components/schemas/SightingDetail" }
               },
               required: %w[data]

        let(:investigator) { create(:user, :investigator) }
        let(:api_key) { create(:api_key, user: investigator) }
        let(:sighting) { create(:sighting, submitter: user, shape: shape) }
        let(:id) { sighting.id }
        let(:"X-Api-Key") { api_key.raw_key }

        before { create(:witness, sighting: sighting) }

        run_test! do |response|
          data = JSON.parse(response.body)["data"]
          expect(data["witnesses"].first).to have_key("contact_info")
        end
      end

      response "401", "unauthorized — missing or invalid API key" do
        schema "$ref": "#/components/schemas/ErrorResponse"

        let(:sighting) { create(:sighting, shape: shape) }
        let(:id) { sighting.id }
        let(:"X-Api-Key") { "invalid-key" }

        run_test! do |response|
          data = JSON.parse(response.body)
          expect(data["error"]).to eq("Unauthorized")
        end
      end

      response "404", "sighting not found" do
        schema "$ref": "#/components/schemas/ErrorResponse"

        let(:id) { 999_999 }
        let(:"X-Api-Key") { api_key.raw_key }

        run_test! do |response|
          data = JSON.parse(response.body)
          expect(data["error"]).to eq("Not found")
        end
      end
    end
  end
end
