# frozen_string_literal: true

require "rails_helper"

# Temporary controller to exercise ApplicationController behavior.
# Defined at top level so Rails routing can find it.
class TestAuthController < ApplicationController
  def index
    policy_scope(User)
    head :ok
  end

  def show
    authorize User, :index?
    head :ok
  end
end

RSpec.describe ApplicationController, type: :request do
  before do
    Rails.application.routes.draw do
      devise_for :users
      get "/test_auth", to: "test_auth#show"
      root "home#index"
    end
  end

  after do
    Rails.application.reload_routes!
  end

  describe "authentication enforcement" do
    it "redirects unauthenticated users to sign in" do
      get "/test_auth"
      expect(response).to redirect_to(new_user_session_path)
    end
  end

  describe "authorization enforcement" do
    it "allows access when authorized" do
      admin = create(:user, :admin)
      sign_in admin
      get "/test_auth"
      expect(response).to have_http_status(:ok)
    end

    it "redirects with alert when not authorized" do
      member = create(:user)
      sign_in member
      get "/test_auth"
      expect(response).to redirect_to(root_path)
      expect(flash[:alert]).to eq("You are not authorized to perform this action.")
    end
  end
end
