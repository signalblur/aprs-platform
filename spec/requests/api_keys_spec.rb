# frozen_string_literal: true

require "rails_helper"

RSpec.describe "ApiKeys" do
  let(:user) { create(:user) }
  let(:admin) { create(:user, :admin) }

  describe "GET /api_keys" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        get api_keys_path
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated" do
      before { sign_in user }

      it "returns success" do
        get api_keys_path
        expect(response).to have_http_status(:ok)
      end

      it "shows the user's API keys" do
        key = create(:api_key, user: user, name: "My Test Key")
        get api_keys_path
        expect(response.body).to include("My Test Key")
        expect(response.body).to include(key.key_prefix)
      end

      it "does not show other users' keys" do
        other = create(:user)
        create(:api_key, user: other, name: "Other User Key")
        get api_keys_path
        expect(response.body).not_to include("Other User Key")
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "shows all API keys" do
        create(:api_key, user: user, name: "User Key Visible")
        create(:api_key, user: admin, name: "Admin Key Visible")
        get api_keys_path
        expect(response.body).to include("User Key Visible")
        expect(response.body).to include("Admin Key Visible")
      end
    end
  end

  describe "GET /api_keys/new" do
    context "when authenticated" do
      before { sign_in user }

      it "returns success" do
        get new_api_key_path
        expect(response).to have_http_status(:ok)
      end

      it "shows the creation form" do
        get new_api_key_path
        expect(response.body).to include("Create API Key")
      end
    end
  end

  describe "POST /api_keys" do
    context "when authenticated" do
      before { sign_in user }

      it "creates an API key" do
        expect {
          post api_keys_path, params: { api_key: { name: "Production Key" } }
        }.to change(ApiKey, :count).by(1)
      end

      it "redirects to show with raw key flash" do
        post api_keys_path, params: { api_key: { name: "Production Key" } }
        expect(response).to redirect_to(api_key_path(ApiKey.last))
        expect(flash[:raw_key]).to be_present
      end

      it "sets the user to current user" do
        post api_keys_path, params: { api_key: { name: "My Key" } }
        expect(ApiKey.last.user).to eq(user)
      end

      it "renders new on invalid params" do
        post api_keys_path, params: { api_key: { name: "" } }
        expect(response).to have_http_status(:unprocessable_content)
      end
    end

    context "when tier limit is reached" do
      before do
        sign_in user
        create(:api_key, user: user)
      end

      it "redirects with unauthorized" do
        post api_keys_path, params: { api_key: { name: "Too Many Keys" } }
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "GET /api_keys/:id" do
    context "when authenticated as owner" do
      before { sign_in user }

      it "returns success" do
        key = create(:api_key, user: user)
        get api_key_path(key)
        expect(response).to have_http_status(:ok)
      end

      it "shows key details" do
        key = create(:api_key, user: user, name: "Detail View Key")
        get api_key_path(key)
        expect(response.body).to include("Detail View Key")
        expect(response.body).to include(key.key_prefix)
      end

      it "shows raw key when flash is set" do
        post api_keys_path, params: { api_key: { name: "New Key" } }
        follow_redirect!
        expect(response.body).to include("Your API key")
      end
    end

    context "when authenticated as another user" do
      it "redirects with unauthorized" do
        other = create(:user)
        sign_in other
        key = create(:api_key, user: user)
        get api_key_path(key)
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "DELETE /api_keys/:id" do
    context "when authenticated as owner" do
      before { sign_in user }

      it "destroys the API key" do
        key = create(:api_key, user: user)
        expect {
          delete api_key_path(key)
        }.to change(ApiKey, :count).by(-1)
        expect(response).to redirect_to(api_keys_path)
      end
    end

    context "when authenticated as another user" do
      it "redirects with unauthorized" do
        other = create(:user)
        sign_in other
        key = create(:api_key, user: user)
        delete api_key_path(key)
        expect(response).to redirect_to(root_path)
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "can destroy any key" do
        key = create(:api_key, user: user)
        expect {
          delete api_key_path(key)
        }.to change(ApiKey, :count).by(-1)
      end
    end
  end
end
