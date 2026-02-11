# frozen_string_literal: true

require "rails_helper"

RSpec.describe InvestigationNotePolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:investigation) { create(:investigation, assigned_investigator: investigator) }
  let(:note) { create(:investigation_note, investigation: investigation, author: investigator) }

  permissions :index? do
    it "grants index to admins" do
      expect(described_class).to permit(admin, note)
    end

    it "grants index to investigators" do
      expect(described_class).to permit(investigator, note)
    end

    it "denies index to members" do
      expect(described_class).not_to permit(member, note)
    end
  end

  permissions :show? do
    it "grants show to admins" do
      expect(described_class).to permit(admin, note)
    end

    it "grants show to assigned investigator" do
      expect(described_class).to permit(investigator, note)
    end

    it "denies show to unassigned investigators" do
      other_investigator = create(:user, :investigator)
      expect(described_class).not_to permit(other_investigator, note)
    end

    it "denies show to members" do
      expect(described_class).not_to permit(member, note)
    end
  end

  permissions :create? do
    it "grants create to admins" do
      expect(described_class).to permit(admin, note)
    end

    it "grants create to assigned investigator" do
      expect(described_class).to permit(investigator, note)
    end

    it "denies create to unassigned investigators" do
      other_investigator = create(:user, :investigator)
      expect(described_class).not_to permit(other_investigator, note)
    end

    it "denies create to members" do
      expect(described_class).not_to permit(member, note)
    end
  end

  permissions :update? do
    it "grants update to admins" do
      expect(described_class).to permit(admin, note)
    end

    it "grants update to the note author" do
      expect(described_class).to permit(investigator, note)
    end

    it "denies update to non-author investigators" do
      other_investigator = create(:user, :investigator)
      expect(described_class).not_to permit(other_investigator, note)
    end

    it "denies update to members" do
      expect(described_class).not_to permit(member, note)
    end
  end

  permissions :destroy? do
    it "grants destroy to admins" do
      expect(described_class).to permit(admin, note)
    end

    it "denies destroy to investigators" do
      expect(described_class).not_to permit(investigator, note)
    end

    it "denies destroy to members" do
      expect(described_class).not_to permit(member, note)
    end
  end

  describe described_class::Scope do
    before do
      note # ensure created
      create(:investigation_note, investigation: create(:investigation))
    end

    it "returns all notes for admins" do
      resolved = described_class.new(admin, InvestigationNote.all).resolve
      expect(resolved.count).to eq(2)
    end

    it "returns notes from assigned investigations for investigators" do
      resolved = described_class.new(investigator, InvestigationNote.all).resolve
      expect(resolved).to contain_exactly(note)
    end

    it "returns no notes for members" do
      resolved = described_class.new(member, InvestigationNote.all).resolve
      expect(resolved).to be_empty
    end
  end
end
