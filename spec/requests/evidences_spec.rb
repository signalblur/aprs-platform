# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Evidences" do
  let(:user) { create(:user) }
  let(:admin) { create(:user, :admin) }
  let(:sighting) { create(:sighting, submitter: user) }

  describe "POST /sightings/:sighting_id/evidences" do
    let(:valid_params) do
      {
        evidence: {
          evidence_type: "photo",
          description: "Photo captured with phone camera",
          file: fixture_file_upload(
            Rails.root.join("spec/fixtures/files/test_photo.jpg"),
            "image/jpeg"
          )
        }
      }
    end

    context "when unauthenticated" do
      it "redirects to sign in" do
        post sighting_evidences_path(sighting), params: valid_params
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated" do
      before { sign_in user }

      it "creates evidence with a file" do
        expect {
          post sighting_evidences_path(sighting), params: valid_params
        }.to change(Evidence, :count).by(1)
        expect(response).to redirect_to(sighting_path(sighting))
      end

      it "sets submitted_by to current user" do
        post sighting_evidences_path(sighting), params: valid_params
        expect(Evidence.last.submitted_by).to eq(user)
      end

      it "associates evidence with the sighting" do
        post sighting_evidences_path(sighting), params: valid_params
        expect(Evidence.last.sighting).to eq(sighting)
      end

      it "redirects back with error on unsupported file type" do
        post sighting_evidences_path(sighting), params: {
          evidence: {
            evidence_type: "photo",
            file: fixture_file_upload(
              Rails.root.join("spec/fixtures/files/bad_file.txt"),
              "text/plain"
            )
          }
        }
        expect(response).to redirect_to(sighting_path(sighting))
        expect(flash[:alert]).to include("unsupported content type")
      end
    end

    context "when tier limit is reached" do
      before do
        sign_in user
        3.times { create(:evidence, sighting: sighting, submitted_by: user) }
      end

      it "redirects with unauthorized" do
        post sighting_evidences_path(sighting), params: valid_params
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "DELETE /sightings/:sighting_id/evidences/:id" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "destroys the evidence" do
        evidence = create(:evidence, sighting: sighting, submitted_by: user)
        expect {
          delete sighting_evidence_path(sighting, evidence)
        }.to change(Evidence, :count).by(-1)
        expect(response).to redirect_to(sighting_path(sighting))
      end
    end

    context "when authenticated as non-admin" do
      before { sign_in user }

      it "redirects with unauthorized" do
        evidence = create(:evidence, sighting: sighting, submitted_by: user)
        delete sighting_evidence_path(sighting, evidence)
        expect(response).to redirect_to(root_path)
      end
    end
  end
end
