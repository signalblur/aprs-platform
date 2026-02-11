# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Dashboard" do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }

  describe "GET /dashboard" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        get dashboard_path
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        get dashboard_path
        expect(response).to have_http_status(:ok)
      end

      it "displays summary statistics" do
        create_list(:sighting, 3)
        create(:investigation)
        create(:user)

        get dashboard_path

        expect(response.body).to include("Total Sightings")
        expect(response.body).to include("Total Users")
        expect(response.body).to include("Open Investigations")
      end

      it "shows sighting status breakdown" do
        create(:sighting, status: :submitted)
        create(:sighting, status: :verified)

        get dashboard_path

        expect(response.body).to include("Sightings by Status")
      end

      it "shows user role breakdown" do
        create(:user)
        create(:user, :investigator)

        get dashboard_path

        expect(response.body).to include("Users by Role")
      end

      it "shows membership tier breakdown" do
        create(:membership, :professional, user: create(:user))

        get dashboard_path

        expect(response.body).to include("Memberships by Tier")
      end

      it "shows investigation status breakdown" do
        create(:investigation, status: :open)
        create(:investigation, :in_progress)

        get dashboard_path

        expect(response.body).to include("Investigations by Status")
      end

      it "shows evidence type breakdown" do
        sighting = create(:sighting)
        create(:evidence, :photo, sighting: sighting, submitted_by: admin)

        get dashboard_path

        expect(response.body).to include("Evidence by Type")
      end

      it "shows top shapes" do
        shape = create(:shape)
        create(:sighting, shape: shape)

        get dashboard_path

        expect(response.body).to include("Top Shapes")
      end

      it "shows recent sightings timeline" do
        create(:sighting)

        get dashboard_path

        expect(response.body).to include("Sightings Over Time")
      end

      it "shows user growth timeline" do
        get dashboard_path

        expect(response.body).to include("User Growth")
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        get dashboard_path
        expect(response).to redirect_to(root_path)
      end
    end

    context "when authenticated as investigator" do
      before { sign_in investigator }

      it "redirects with unauthorized" do
        get dashboard_path
        expect(response).to redirect_to(root_path)
      end
    end
  end
end
