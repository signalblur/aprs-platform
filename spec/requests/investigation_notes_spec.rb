# frozen_string_literal: true

require "rails_helper"

RSpec.describe "InvestigationNotes" do
  let(:admin) { create(:user, :admin) }
  let(:investigator) { create(:user, :investigator) }
  let(:member) { create(:user) }
  let(:investigation) { create(:investigation, assigned_investigator: investigator) }

  describe "POST /investigations/:investigation_id/notes" do
    context "when authenticated as assigned investigator" do
      before { sign_in investigator }

      it "creates a note" do
        expect {
          post investigation_notes_path(investigation), params: {
            investigation_note: { content: "Initial observations recorded from the field", note_type: "general" }
          }
        }.to change(InvestigationNote, :count).by(1)

        expect(response).to redirect_to(investigation_path(investigation))
        note = InvestigationNote.last
        expect(note.author).to eq(investigator)
        expect(note.investigation).to eq(investigation)
      end

      it "redirects with error on invalid params" do
        post investigation_notes_path(investigation), params: {
          investigation_note: { content: "", note_type: "general" }
        }
        expect(response).to redirect_to(investigation_path(investigation))
        expect(flash[:alert]).to be_present
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "creates a note" do
        expect {
          post investigation_notes_path(investigation), params: {
            investigation_note: { content: "Admin note on investigation progress", note_type: "status_change" }
          }
        }.to change(InvestigationNote, :count).by(1)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        post investigation_notes_path(investigation), params: {
          investigation_note: { content: "Unauthorized member note attempt", note_type: "general" }
        }
        expect(response).to redirect_to(root_path)
      end
    end

    context "when authenticated as unassigned investigator" do
      it "redirects with unauthorized" do
        other_investigator = create(:user, :investigator)
        sign_in other_investigator
        post investigation_notes_path(investigation), params: {
          investigation_note: { content: "Unassigned investigator note attempt", note_type: "general" }
        }
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "DELETE /investigations/:investigation_id/notes/:id" do
    context "when authenticated as admin" do
      before { sign_in admin }

      it "destroys the note" do
        note = create(:investigation_note, investigation: investigation, author: investigator)
        expect {
          delete investigation_note_path(investigation, note)
        }.to change(InvestigationNote, :count).by(-1)
        expect(response).to redirect_to(investigation_path(investigation))
      end
    end

    context "when authenticated as investigator" do
      before { sign_in investigator }

      it "redirects with unauthorized" do
        note = create(:investigation_note, investigation: investigation, author: investigator)
        delete investigation_note_path(investigation, note)
        expect(response).to redirect_to(root_path)
      end
    end

    context "when authenticated as member" do
      before { sign_in member }

      it "redirects with unauthorized" do
        note = create(:investigation_note, investigation: investigation, author: investigator)
        delete investigation_note_path(investigation, note)
        expect(response).to redirect_to(root_path)
      end
    end
  end
end
