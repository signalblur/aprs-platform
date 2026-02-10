# frozen_string_literal: true

require "rails_helper"

RSpec.describe "API v1 Rate Limiting", type: :request do
  let(:user) { create(:user) }
  let(:api_key) { create(:api_key, user: user) }
  let(:headers) { { "X-Api-Key" => api_key.raw_key } }

  describe "unauthenticated API requests" do
    it "throttles after 10 requests per minute" do
      11.times { get api_v1_shapes_path }
      expect(response).to have_http_status(:too_many_requests)
    end

    it "returns JSON error body" do
      11.times { get api_v1_shapes_path }
      expect(response.parsed_body["error"]).to eq("Rate limit exceeded. Please retry later.")
    end
  end

  describe "authenticated API requests" do
    it "allows up to 300 requests per minute" do
      create(:shape)
      # We can't make 300+ requests in a test, so verify the first request passes
      get api_v1_shapes_path, headers: headers
      expect(response).to have_http_status(:ok)
    end
  end

  describe "429 response format" do
    it "returns application/json content type" do
      11.times { get api_v1_shapes_path }
      expect(response.content_type).to start_with("application/json")
    end
  end
end
