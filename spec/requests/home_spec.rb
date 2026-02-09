# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Home", type: :request do
  describe "GET /" do
    it "returns http success without authentication" do
      get root_path
      expect(response).to have_http_status(:ok)
    end
  end
end
