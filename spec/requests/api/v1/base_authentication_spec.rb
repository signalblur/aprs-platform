# frozen_string_literal: true

require "rails_helper"

RSpec.describe "API v1 Authentication", type: :request do
  let(:user) { create(:user) }
  let(:api_key) { create(:api_key, user: user) }
  let(:valid_headers) { { "X-Api-Key" => api_key.raw_key } }

  # Use shapes index as a lightweight endpoint for auth testing
  let(:test_path) { api_v1_shapes_path }

  describe "missing API key" do
    it "returns 401 Unauthorized" do
      get test_path
      expect(response).to have_http_status(:unauthorized)
    end

    it "returns JSON error body" do
      get test_path
      expect(response.parsed_body["error"]).to eq("Unauthorized")
    end
  end

  describe "blank API key" do
    it "returns 401 Unauthorized" do
      get test_path, headers: { "X-Api-Key" => "" }
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "invalid API key" do
    it "returns 401 Unauthorized" do
      get test_path, headers: { "X-Api-Key" => "invalid_key_here" }
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "inactive API key" do
    let(:api_key) { create(:api_key, :inactive, user: user) }

    it "returns 401 Unauthorized" do
      get test_path, headers: valid_headers
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "expired API key" do
    let(:api_key) { create(:api_key, :expired, user: user) }

    it "returns 401 Unauthorized" do
      get test_path, headers: valid_headers
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "locked user account" do
    let(:user) { create(:user, locked_at: Time.current) }

    it "returns 401 Unauthorized" do
      get test_path, headers: valid_headers
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "unconfirmed user account" do
    let(:user) { create(:user, confirmed_at: nil) }

    it "returns 401 Unauthorized" do
      get test_path, headers: valid_headers
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "valid API key" do
    it "returns 200" do
      create(:shape)
      get test_path, headers: valid_headers
      expect(response).to have_http_status(:ok)
    end

    it "returns JSON content type" do
      create(:shape)
      get test_path, headers: valid_headers
      expect(response.content_type).to start_with("application/json")
    end

    it "updates last_used_at on the API key" do
      create(:shape)
      headers = valid_headers # evaluate before change matcher triggers reload
      expect { get test_path, headers: headers }
        .to change { api_key.reload.last_used_at }.from(nil)
    end

    it "does not set session cookies" do
      create(:shape)
      get test_path, headers: valid_headers
      expect(response.headers["Set-Cookie"]).to be_nil
    end
  end

  describe "error responses" do
    it "returns 404 JSON for record not found" do
      get api_v1_sighting_path(id: 999_999), headers: valid_headers
      expect(response).to have_http_status(:not_found)
      expect(response.parsed_body["error"]).to eq("Not found")
    end

    it "returns 403 JSON for unauthorized actions" do
      # Pundit::NotAuthorizedError is rescued to render 403
      # We trigger this by making a non-admin user attempt an admin-only action
      # Since all API endpoints are read-only (show?/index? = true for all),
      # we simulate the error directly via controller
      allow_any_instance_of(SightingPolicy).to receive(:show?).and_return(false) # rubocop:disable RSpec/AnyInstance
      sighting = create(:sighting)
      get api_v1_sighting_path(sighting), headers: valid_headers
      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body["error"]).to eq("Forbidden")
    end
  end
end
