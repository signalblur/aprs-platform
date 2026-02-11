# frozen_string_literal: true

require "swagger_helper"

RSpec.describe "API v1 Investigations" do
  let(:investigator) { create(:user, :investigator) }
  let(:api_key) { create(:api_key, user: investigator) }

  path "/api/v1/investigations" do
    get "Lists investigations with optional filters" do
      tags "Investigations"
      produces "application/json"
      security [api_key: []]

      parameter name: :status, in: :query, type: :string, required: false,
                enum: %w[open in_progress closed_resolved closed_unresolved closed_inconclusive],
                description: "Filter by investigation status"
      parameter name: :priority, in: :query, type: :string, required: false,
                enum: %w[low medium high critical],
                description: "Filter by priority level"
      parameter name: :page, in: :query, type: :integer, required: false,
                description: "Page number (default: 1)"

      response "200", "paginated investigations list" do
        schema type: :object,
               properties: {
                 data: { type: :array, items: { "$ref": "#/components/schemas/InvestigationSummary" } },
                 meta: { "$ref": "#/components/schemas/PaginationMeta" }
               },
               required: %w[data meta]

        let(:"X-Api-Key") { api_key.raw_key }

        before { create(:investigation) }

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

  path "/api/v1/investigations/{id}" do
    get "Retrieves a single investigation with associations" do
      tags "Investigations"
      produces "application/json"
      security [api_key: []]

      parameter name: :id, in: :path, type: :integer, required: true,
                description: "Investigation ID"

      response "200", "investigation detail (investigator view — includes findings and notes)" do
        schema type: :object,
               properties: {
                 data: { "$ref": "#/components/schemas/InvestigationDetail" }
               },
               required: %w[data]

        let(:investigation) { create(:investigation, :closed_resolved, findings: "Documented findings report") }
        let(:id) { investigation.id }
        let(:"X-Api-Key") { api_key.raw_key }

        before { create(:investigation_note, investigation: investigation, author: investigator) }

        run_test! do |response|
          data = JSON.parse(response.body)["data"]
          expect(data["case_number"]).to eq(investigation.case_number)
          expect(data["findings"]).to eq("Documented findings report")
          expect(data["notes"]).to be_an(Array)
        end
      end

      response "200", "investigation detail (member view — excludes findings and notes)" do
        schema type: :object,
               properties: {
                 data: { "$ref": "#/components/schemas/InvestigationDetail" }
               },
               required: %w[data]

        let(:member) { create(:user) }
        let(:api_key) { create(:api_key, user: member) }
        let(:investigation) { create(:investigation, :closed_resolved, findings: "Secret findings") }
        let(:id) { investigation.id }
        let(:"X-Api-Key") { api_key.raw_key }

        before do
          create(:sighting, submitter: member, investigation: investigation)
        end

        run_test! do |response|
          data = JSON.parse(response.body)["data"]
          expect(data).not_to have_key("findings")
          expect(data).not_to have_key("notes")
        end
      end

      response "401", "unauthorized — missing or invalid API key" do
        schema "$ref": "#/components/schemas/ErrorResponse"

        let(:investigation) { create(:investigation) }
        let(:id) { investigation.id }
        let(:"X-Api-Key") { "invalid-key" }

        run_test! do |response|
          data = JSON.parse(response.body)
          expect(data["error"]).to eq("Unauthorized")
        end
      end

      response "404", "investigation not found" do
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
