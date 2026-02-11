# frozen_string_literal: true

require "rails_helper"

RSpec.describe InvestigationPolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:investigation) { create(:investigation, :with_investigator) }

  permissions :index? do
    it "grants index to admins" do
      expect(described_class).to permit(admin, investigation)
    end

    it "grants index to investigators" do
      expect(described_class).to permit(investigator, investigation)
    end

    it "grants index to members" do
      expect(described_class).to permit(member, investigation)
    end
  end

  permissions :show? do
    it "grants show to admins" do
      expect(described_class).to permit(admin, investigation)
    end

    it "grants show to investigators" do
      expect(described_class).to permit(investigator, investigation)
    end

    it "denies show to members with no linked sightings" do
      expect(described_class).not_to permit(member, investigation)
    end

    it "grants show to members with a linked sighting" do
      create(:sighting, submitter: member, investigation: investigation)
      expect(described_class).to permit(member, investigation)
    end
  end

  permissions :create? do
    it "grants create to admins" do
      expect(described_class).to permit(admin, described_class)
    end

    it "denies create to investigators" do
      expect(described_class).not_to permit(investigator, described_class)
    end

    it "denies create to members" do
      expect(described_class).not_to permit(member, described_class)
    end
  end

  permissions :update? do
    it "grants update to admins" do
      expect(described_class).to permit(admin, investigation)
    end

    it "grants update to the assigned investigator" do
      expect(described_class).to permit(investigation.assigned_investigator, investigation)
    end

    it "denies update to unassigned investigators" do
      other_investigator = create(:user, :investigator)
      expect(described_class).not_to permit(other_investigator, investigation)
    end

    it "denies update to members" do
      expect(described_class).not_to permit(member, investigation)
    end
  end

  permissions :destroy? do
    it "grants destroy to admins" do
      expect(described_class).to permit(admin, investigation)
    end

    it "denies destroy to investigators" do
      expect(described_class).not_to permit(investigator, investigation)
    end

    it "denies destroy to members" do
      expect(described_class).not_to permit(member, investigation)
    end
  end

  permissions :link_sighting? do
    it "grants link_sighting to admins" do
      expect(described_class).to permit(admin, investigation)
    end

    it "denies link_sighting to investigators" do
      expect(described_class).not_to permit(investigator, investigation)
    end

    it "denies link_sighting to members" do
      expect(described_class).not_to permit(member, investigation)
    end
  end

  describe "#show_findings?" do
    it "returns true for admins" do
      policy = described_class.new(admin, investigation)
      expect(policy.show_findings?).to be true
    end

    it "returns true for investigators" do
      policy = described_class.new(investigator, investigation)
      expect(policy.show_findings?).to be true
    end

    it "returns false for members" do
      policy = described_class.new(member, investigation)
      expect(policy.show_findings?).to be false
    end
  end

  describe described_class::Scope do
    let!(:inv_with_member_sighting) do
      inv = create(:investigation)
      create(:sighting, submitter: member, investigation: inv)
      inv
    end
    let!(:inv_without_member_sighting) { create(:investigation) }

    it "returns all investigations for admins" do
      resolved = described_class.new(admin, Investigation.all).resolve
      expect(resolved).to contain_exactly(inv_with_member_sighting, inv_without_member_sighting)
    end

    it "returns all investigations for investigators" do
      resolved = described_class.new(investigator, Investigation.all).resolve
      expect(resolved).to contain_exactly(inv_with_member_sighting, inv_without_member_sighting)
    end

    it "returns only linked investigations for members" do
      resolved = described_class.new(member, Investigation.all).resolve
      expect(resolved).to contain_exactly(inv_with_member_sighting)
    end
  end
end
