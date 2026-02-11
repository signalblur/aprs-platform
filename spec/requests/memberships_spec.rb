# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Memberships" do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }

  describe "GET /memberships" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        get memberships_path
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        get memberships_path
        expect(response).to have_http_status(:ok)
      end

      it "shows all memberships" do
        membership = create(:membership, :professional, user: member)
        get memberships_path
        expect(response.body).to include(member.email)
        expect(response.body).to include("professional")
      end

      it "filters by tier" do
        create(:membership, :professional, user: member)
        other_user = create(:user)
        create(:membership, :organization, user: other_user)
        get memberships_path, params: { tier: "professional" }
        expect(response.body).to include(member.email)
        expect(response.body).not_to include(other_user.email)
      end

      it "filters by active status" do
        create(:membership, user: member)
        other_user = create(:user)
        create(:membership, :inactive, user: other_user)
        get memberships_path, params: { active: "true" }
        expect(response.body).to include(member.email)
        expect(response.body).not_to include(other_user.email)
      end

      it "paginates results" do
        create_list(:membership, 21)
        get memberships_path
        expect(response.body).to include("pagy")
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        get memberships_path
        expect(response).to redirect_to(root_path)
      end
    end

    context "when authenticated as investigator" do
      before { sign_in investigator }

      it "redirects with unauthorized" do
        get memberships_path
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "GET /memberships/:id" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        membership = create(:membership, user: member)
        get membership_path(membership)
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        membership = create(:membership, user: member)
        get membership_path(membership)
        expect(response).to have_http_status(:ok)
      end

      it "shows membership details" do
        membership = create(:membership, :professional, user: member)
        get membership_path(membership)
        expect(response.body).to include(member.email)
        expect(response.body).to include("Professional")
      end

      it "returns 404 for non-existent membership" do
        get membership_path(id: 999_999)
        expect(response).to have_http_status(:not_found)
      end
    end

    context "when authenticated as membership owner" do
      before { sign_in member }

      it "returns success for own membership" do
        membership = create(:membership, user: member)
        get membership_path(membership)
        expect(response).to have_http_status(:ok)
      end
    end

    context "when authenticated as another member" do
      it "redirects with unauthorized" do
        other = create(:user)
        sign_in other
        membership = create(:membership, user: member)
        get membership_path(membership)
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "GET /users/:user_id/memberships/new" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        get new_user_membership_path(member)
        expect(response).to have_http_status(:ok)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        get new_user_membership_path(member)
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "POST /users/:user_id/memberships" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "creates a membership with valid params" do
        expect {
          post user_memberships_path(member), params: {
            membership: {
              tier: "professional",
              notes: "Upgraded for research",
              starts_at: Time.current.iso8601
            }
          }
        }.to change(Membership, :count).by(1)

        expect(response).to redirect_to(membership_path(Membership.last))
      end

      it "sets granted_by to the current admin" do
        post user_memberships_path(member), params: {
          membership: {
            tier: "professional",
            starts_at: Time.current.iso8601
          }
        }
        expect(Membership.last.granted_by).to eq(admin)
      end

      it "deactivates existing active membership" do
        existing = create(:membership, user: member)
        post user_memberships_path(member), params: {
          membership: {
            tier: "organization",
            starts_at: Time.current.iso8601
          }
        }
        expect(existing.reload).not_to be_active
      end

      it "renders new on invalid params" do
        post user_memberships_path(member), params: {
          membership: { tier: "professional", starts_at: "" }
        }
        expect(response).to have_http_status(:unprocessable_content)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        post user_memberships_path(member), params: {
          membership: { tier: "professional", starts_at: Time.current.iso8601 }
        }
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "GET /memberships/:id/edit" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        membership = create(:membership, user: member)
        get edit_membership_path(membership)
        expect(response).to have_http_status(:ok)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        membership = create(:membership, user: member)
        get edit_membership_path(membership)
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "PATCH /memberships/:id" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "updates the membership" do
        membership = create(:membership, user: member)
        patch membership_path(membership), params: {
          membership: { notes: "Updated notes" }
        }
        expect(response).to redirect_to(membership_path(membership))
        expect(membership.reload.notes).to eq("Updated notes")
      end

      it "can deactivate a membership" do
        membership = create(:membership, user: member)
        patch membership_path(membership), params: {
          membership: { active: false }
        }
        expect(membership.reload).not_to be_active
      end

      it "cannot change the tier via update" do
        membership = create(:membership, user: member)
        patch membership_path(membership), params: {
          membership: { tier: "organization" }
        }
        expect(membership.reload.tier).to eq("free")
      end

      it "renders edit on invalid update" do
        membership = create(:membership, user: member)
        allow_any_instance_of(Membership).to receive(:update).and_return(false) # rubocop:disable RSpec/AnyInstance
        patch membership_path(membership), params: {
          membership: { notes: "test" }
        }
        expect(response).to have_http_status(:unprocessable_content)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        membership = create(:membership, user: member)
        patch membership_path(membership), params: {
          membership: { notes: "Hacker attempt" }
        }
        expect(response).to redirect_to(root_path)
      end
    end
  end
end
