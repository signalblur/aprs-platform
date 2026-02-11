# frozen_string_literal: true

require "rails_helper"

RSpec.describe "API v1 Investigations", type: :request do
  let(:user) { create(:user) }
  let(:api_key) { create(:api_key, user: user) }
  let(:headers) { { "X-Api-Key" => api_key.raw_key } }

  describe "GET /api/v1/investigations" do
    it "returns 401 without API key" do
      get api_v1_investigations_path
      expect(response).to have_http_status(:unauthorized)
    end

    it "returns 200 with valid API key" do
      get api_v1_investigations_path, headers: headers
      expect(response).to have_http_status(:ok)
    end

    it "returns JSON content type" do
      get api_v1_investigations_path, headers: headers
      expect(response.content_type).to start_with("application/json")
    end

    context "when user is a member" do
      it "only returns investigations linked to member sightings" do
        linked_inv = create(:investigation)
        create(:sighting, submitter: user, investigation: linked_inv)
        create(:investigation) # unlinked

        get api_v1_investigations_path, headers: headers

        data = response.parsed_body["data"]
        expect(data.length).to eq(1)
        expect(data.first["id"]).to eq(linked_inv.id)
      end
    end

    context "when user is an investigator" do
      let(:user) { create(:user, :investigator) }

      it "returns all investigations" do
        create_list(:investigation, 3)
        get api_v1_investigations_path, headers: headers
        expect(response.parsed_body["data"].length).to eq(3)
      end
    end

    context "when user is an admin" do
      let(:user) { create(:user, :admin) }

      it "returns all investigations" do
        create_list(:investigation, 3)
        get api_v1_investigations_path, headers: headers
        expect(response.parsed_body["data"].length).to eq(3)
      end
    end

    context "with investigations" do
      let(:user) { create(:user, :investigator) }
      let!(:investigation) { create(:investigation) }

      it "returns data array" do
        get api_v1_investigations_path, headers: headers
        expect(response.parsed_body["data"]).to be_an(Array)
      end

      it "returns meta with pagination" do
        get api_v1_investigations_path, headers: headers
        meta = response.parsed_body["meta"]
        expect(meta).to include("page", "per_page", "total", "total_pages")
      end

      it "includes investigation fields" do
        get api_v1_investigations_path, headers: headers
        inv_data = response.parsed_body["data"].first
        expect(inv_data["case_number"]).to eq(investigation.case_number)
        expect(inv_data["title"]).to eq(investigation.title)
        expect(inv_data["status"]).to eq("open")
        expect(inv_data["priority"]).to eq("low")
      end

      it "includes ISO 8601 timestamps" do
        get api_v1_investigations_path, headers: headers
        inv_data = response.parsed_body["data"].first
        expect { Time.iso8601(inv_data["opened_at"]) }.not_to raise_error
        expect { Time.iso8601(inv_data["created_at"]) }.not_to raise_error
      end

      it "includes sighting_count" do
        create(:sighting, investigation: investigation)
        get api_v1_investigations_path, headers: headers
        expect(response.parsed_body["data"].first["sighting_count"]).to eq(1)
      end
    end

    describe "pagination" do
      let(:user) { create(:user, :investigator) }

      before { create_list(:investigation, 25) }

      it "defaults to 20 per page" do
        get api_v1_investigations_path, headers: headers
        expect(response.parsed_body["data"].length).to eq(20)
      end

      it "supports page param" do
        get api_v1_investigations_path, params: { page: 2 }, headers: headers
        expect(response.parsed_body["data"].length).to eq(5)
        expect(response.parsed_body["meta"]["page"]).to eq(2)
      end

      it "handles overflow page gracefully" do
        get api_v1_investigations_path, params: { page: 999 }, headers: headers
        expect(response).to have_http_status(:not_found)
      end
    end

    describe "filters" do
      let(:user) { create(:user, :investigator) }

      it "filters by status" do
        create(:investigation, :in_progress)
        create(:investigation, status: :open)
        get api_v1_investigations_path, params: { status: "in_progress" }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
        expect(response.parsed_body["data"].first["status"]).to eq("in_progress")
      end

      it "filters by priority" do
        create(:investigation, :high_priority)
        create(:investigation)
        get api_v1_investigations_path, params: { priority: "high" }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
        expect(response.parsed_body["data"].first["priority"]).to eq("high")
      end

      it "ignores blank filter params" do
        create(:investigation)
        get api_v1_investigations_path, params: { status: "", priority: "" }, headers: headers
        expect(response.parsed_body["data"].length).to eq(1)
      end
    end
  end

  describe "GET /api/v1/investigations/:id" do
    let(:user) { create(:user, :investigator) }
    let!(:investigation) { create(:investigation, :closed_resolved, findings: "Investigation findings report") }

    it "returns 401 without API key" do
      get api_v1_investigation_path(investigation)
      expect(response).to have_http_status(:unauthorized)
    end

    it "returns 200 with valid API key" do
      get api_v1_investigation_path(investigation), headers: headers
      expect(response).to have_http_status(:ok)
    end

    it "returns 404 for non-existent investigation" do
      get api_v1_investigation_path(id: 999_999), headers: headers
      expect(response).to have_http_status(:not_found)
    end

    it "returns JSON content type" do
      get api_v1_investigation_path(investigation), headers: headers
      expect(response.content_type).to start_with("application/json")
    end

    it "returns investigation detail" do
      get api_v1_investigation_path(investigation), headers: headers
      data = response.parsed_body["data"]
      expect(data["case_number"]).to eq(investigation.case_number)
      expect(data["title"]).to eq(investigation.title)
      expect(data["description"]).to eq(investigation.description)
    end

    it "includes linked sightings" do
      create(:sighting, investigation: investigation)
      get api_v1_investigation_path(investigation), headers: headers
      data = response.parsed_body["data"]
      expect(data["sightings"]).to be_an(Array)
      expect(data["sightings"].length).to eq(1)
    end

    describe "findings and notes gating" do
      before do
        create(:investigation_note, investigation: investigation, author: create(:user, :investigator))
      end

      context "when user is an investigator" do
        it "includes findings" do
          get api_v1_investigation_path(investigation), headers: headers
          expect(response.parsed_body["data"]["findings"]).to eq("Investigation findings report")
        end

        it "includes notes" do
          get api_v1_investigation_path(investigation), headers: headers
          data = response.parsed_body["data"]
          expect(data["notes"]).to be_an(Array)
          expect(data["notes"].length).to eq(1)
        end
      end

      context "when user is an admin" do
        let(:user) { create(:user, :admin) }

        it "includes findings" do
          get api_v1_investigation_path(investigation), headers: headers
          expect(response.parsed_body["data"]["findings"]).to eq("Investigation findings report")
        end
      end

      context "when user is a member" do
        let(:user) { create(:user) }

        before do
          create(:sighting, submitter: user, investigation: investigation)
        end

        it "excludes findings" do
          get api_v1_investigation_path(investigation), headers: headers
          expect(response.parsed_body["data"]).not_to have_key("findings")
        end

        it "excludes notes" do
          get api_v1_investigation_path(investigation), headers: headers
          expect(response.parsed_body["data"]).not_to have_key("notes")
        end
      end
    end

    context "when member has no linked sightings" do
      let(:user) { create(:user) }

      it "returns 403 forbidden" do
        get api_v1_investigation_path(investigation), headers: headers
        expect(response).to have_http_status(:forbidden)
      end
    end
  end
end
