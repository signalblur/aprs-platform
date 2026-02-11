# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Investigations" do
  let(:admin) { create(:user, :admin) }
  let(:investigator) { create(:user, :investigator) }
  let(:member) { create(:user) }

  describe "GET /investigations" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        get investigations_path
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        get investigations_path
        expect(response).to have_http_status(:ok)
      end

      it "shows all investigations" do
        inv = create(:investigation, title: "Denver Lights Case Study")
        get investigations_path
        expect(response.body).to include("Denver Lights Case Study")
        expect(response.body).to include(inv.case_number)
      end

      it "paginates results" do
        create_list(:investigation, 21)
        get investigations_path
        expect(response.body).to include("pagy")
      end

      it "filters by status" do
        open_inv = create(:investigation, status: :open)
        create(:investigation, :in_progress)
        get investigations_path, params: { status: "open" }
        expect(response.body).to include(open_inv.title)
      end

      it "filters by priority" do
        high = create(:investigation, :high_priority, title: "High Priority Test Case")
        create(:investigation)
        get investigations_path, params: { priority: "high" }
        expect(response.body).to include(high.title)
      end

      it "filters by assigned_to" do
        inv = create(:investigation, assigned_investigator: investigator)
        create(:investigation)
        get investigations_path, params: { assigned_to: investigator.id }
        expect(response.body).to include(inv.title)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "returns success" do
        get investigations_path
        expect(response).to have_http_status(:ok)
      end

      it "shows only investigations linked to member sightings" do
        linked_inv = create(:investigation, title: "Linked Investigation Case")
        create(:sighting, submitter: member, investigation: linked_inv)
        unlinked_inv = create(:investigation, title: "Unlinked Investigation Case")

        get investigations_path

        expect(response.body).to include(linked_inv.title)
        expect(response.body).not_to include(unlinked_inv.title)
      end
    end
  end

  describe "GET /investigations/:id" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        investigation = create(:investigation)
        get investigation_path(investigation)
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        investigation = create(:investigation)
        get investigation_path(investigation)
        expect(response).to have_http_status(:ok)
      end

      it "shows investigation details" do
        investigation = create(:investigation, title: "Test Case Study Details")
        get investigation_path(investigation)
        expect(response.body).to include("Test Case Study Details")
        expect(response.body).to include(investigation.case_number)
      end

      it "shows findings for admins" do
        investigation = create(:investigation, :closed_resolved, findings: "Conclusive analysis report")
        get investigation_path(investigation)
        expect(response.body).to include("Conclusive analysis report")
      end

      it "returns 404 for non-existent investigation" do
        get investigation_path(id: 999_999)
        expect(response).to have_http_status(:not_found)
      end
    end

    context "when authenticated as investigator" do
      before { sign_in investigator }

      it "returns success" do
        investigation = create(:investigation)
        get investigation_path(investigation)
        expect(response).to have_http_status(:ok)
      end

      it "shows findings for investigators" do
        investigation = create(:investigation, :closed_resolved, findings: "Investigation findings text")
        get investigation_path(investigation)
        expect(response.body).to include("Investigation findings text")
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "denies access when no linked sightings" do
        investigation = create(:investigation)
        get investigation_path(investigation)
        expect(response).to redirect_to(root_path)
      end

      it "grants access when member has a linked sighting" do
        investigation = create(:investigation, title: "Member Linked Case")
        create(:sighting, submitter: member, investigation: investigation)
        get investigation_path(investigation)
        expect(response).to have_http_status(:ok)
        expect(response.body).to include("Member Linked Case")
      end

      it "hides findings from members" do
        investigation = create(:investigation, :closed_resolved, findings: "Secret Findings Report")
        create(:sighting, submitter: member, investigation: investigation)
        get investigation_path(investigation)
        expect(response.body).not_to include("Secret Findings Report")
      end
    end
  end

  describe "GET /investigations/new" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        get new_investigation_path
        expect(response).to have_http_status(:ok)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        get new_investigation_path
        expect(response).to redirect_to(root_path)
      end
    end

    context "when authenticated as investigator" do
      before { sign_in investigator }

      it "redirects with unauthorized" do
        get new_investigation_path
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "POST /investigations" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "creates an investigation with valid params" do
        expect {
          post investigations_path, params: {
            investigation: {
              title: "New Denver Investigation Case",
              description: "Multiple sighting reports",
              priority: "high",
              opened_at: Time.current.iso8601
            }
          }
        }.to change(Investigation, :count).by(1)

        expect(response).to redirect_to(investigation_path(Investigation.last))
      end

      it "renders new on invalid params" do
        post investigations_path, params: {
          investigation: { title: "No", opened_at: "" }
        }
        expect(response).to have_http_status(:unprocessable_entity)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        post investigations_path, params: {
          investigation: { title: "Attempt to create case study", opened_at: Time.current.iso8601 }
        }
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "GET /investigations/:id/edit" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        investigation = create(:investigation)
        get edit_investigation_path(investigation)
        expect(response).to have_http_status(:ok)
      end
    end

    context "when authenticated as assigned investigator" do
      it "returns success" do
        investigation = create(:investigation, assigned_investigator: investigator)
        sign_in investigator
        get edit_investigation_path(investigation)
        expect(response).to have_http_status(:ok)
      end
    end

    context "when authenticated as unassigned investigator" do
      before { sign_in investigator }

      it "redirects with unauthorized" do
        investigation = create(:investigation, :with_investigator)
        get edit_investigation_path(investigation)
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "PATCH /investigations/:id" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "updates the investigation" do
        investigation = create(:investigation)
        patch investigation_path(investigation), params: {
          investigation: { title: "Updated Title Investigation Case" }
        }
        expect(response).to redirect_to(investigation_path(investigation))
        expect(investigation.reload.title).to eq("Updated Title Investigation Case")
      end

      it "renders edit on invalid params" do
        investigation = create(:investigation)
        patch investigation_path(investigation), params: {
          investigation: { title: "No" }
        }
        expect(response).to have_http_status(:unprocessable_entity)
      end
    end

    context "when authenticated as assigned investigator" do
      it "updates the investigation" do
        investigation = create(:investigation, assigned_investigator: investigator)
        sign_in investigator
        patch investigation_path(investigation), params: {
          investigation: { status: "in_progress" }
        }
        expect(response).to redirect_to(investigation_path(investigation))
        expect(investigation.reload.status).to eq("in_progress")
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        investigation = create(:investigation)
        patch investigation_path(investigation), params: {
          investigation: { title: "Unauthorized Update Attempt" }
        }
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "DELETE /investigations/:id" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "destroys the investigation" do
        investigation = create(:investigation)
        expect {
          delete investigation_path(investigation)
        }.to change(Investigation, :count).by(-1)
        expect(response).to redirect_to(investigations_path)
      end
    end

    context "when authenticated as investigator" do
      before { sign_in investigator }

      it "redirects with unauthorized" do
        investigation = create(:investigation)
        delete investigation_path(investigation)
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "POST /investigations/:id/link_sighting" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "links a sighting to the investigation" do
        investigation = create(:investigation)
        sighting = create(:sighting)

        post link_sighting_investigation_path(investigation), params: { sighting_id: sighting.id }

        expect(response).to redirect_to(investigation_path(investigation))
        expect(sighting.reload.investigation).to eq(investigation)
      end
    end

    context "when authenticated as investigator" do
      before { sign_in investigator }

      it "redirects with unauthorized" do
        investigation = create(:investigation, assigned_investigator: investigator)
        sighting = create(:sighting)

        post link_sighting_investigation_path(investigation), params: { sighting_id: sighting.id }
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "DELETE /investigations/:id/unlink_sighting" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "unlinks a sighting from the investigation" do
        investigation = create(:investigation)
        sighting = create(:sighting, investigation: investigation)

        delete unlink_sighting_investigation_path(investigation), params: { sighting_id: sighting.id }

        expect(response).to redirect_to(investigation_path(investigation))
        expect(sighting.reload.investigation).to be_nil
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        investigation = create(:investigation)
        sighting = create(:sighting, investigation: investigation)

        delete unlink_sighting_investigation_path(investigation), params: { sighting_id: sighting.id }
        expect(response).to redirect_to(root_path)
      end
    end
  end
end
