# frozen_string_literal: true

require "rails_helper"

RSpec.describe EvidencePolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:sighting) { create(:sighting, submitter: member) }
  let(:evidence) { create(:evidence, sighting: sighting, submitted_by: member) }

  permissions :index? do
    it "grants index access to admins" do
      expect(described_class).to permit(admin, evidence)
    end

    it "grants index access to members" do
      expect(described_class).to permit(member, evidence)
    end

    it "grants index access to investigators" do
      expect(described_class).to permit(investigator, evidence)
    end
  end

  permissions :show? do
    it "grants show access to admins" do
      expect(described_class).to permit(admin, evidence)
    end

    it "grants show access to members" do
      expect(described_class).to permit(member, evidence)
    end

    it "grants show access to investigators" do
      expect(described_class).to permit(investigator, evidence)
    end
  end

  permissions :create? do
    it "grants create access to admins" do
      expect(described_class).to permit(admin, Evidence.new(sighting: sighting))
    end

    it "grants create access to members within tier limit" do
      expect(described_class).to permit(member, Evidence.new(sighting: sighting))
    end

    it "grants create access to investigators within tier limit" do
      expect(described_class).to permit(investigator, Evidence.new(sighting: sighting))
    end

    it "grants create access when no sighting is set" do
      expect(described_class).to permit(member, Evidence.new)
    end

    it "denies create when per-sighting evidence limit is reached" do
      create_list(:evidence, 3, sighting: sighting, submitted_by: member)
      expect(described_class).not_to permit(member, Evidence.new(sighting: sighting))
    end

    it "grants create when user has professional tier" do
      create(:membership, :professional, user: member)
      create_list(:evidence, 3, sighting: sighting, submitted_by: member)
      expect(described_class).to permit(member, Evidence.new(sighting: sighting))
    end

    it "always grants create access to admins regardless of count" do
      create_list(:evidence, 5, sighting: sighting, submitted_by: admin)
      expect(described_class).to permit(admin, Evidence.new(sighting: sighting))
    end
  end

  permissions :update? do
    it "grants update access to admins" do
      expect(described_class).to permit(admin, evidence)
    end

    it "grants update access to the evidence submitter" do
      expect(described_class).to permit(member, evidence)
    end

    it "denies update access to non-submitter members" do
      other_member = create(:user)
      expect(described_class).not_to permit(other_member, evidence)
    end

    it "denies update access to investigators who did not submit" do
      expect(described_class).not_to permit(investigator, evidence)
    end
  end

  permissions :destroy? do
    it "grants destroy access to admins" do
      expect(described_class).to permit(admin, evidence)
    end

    it "denies destroy access to members" do
      expect(described_class).not_to permit(member, evidence)
    end

    it "denies destroy access to investigators" do
      expect(described_class).not_to permit(investigator, evidence)
    end
  end

  describe described_class::Scope do
    let!(:evidences) { create_list(:evidence, 3) }

    it "returns all evidences for admins" do
      resolved_scope = described_class.new(admin, Evidence.all).resolve
      expect(resolved_scope).to match_array(evidences)
    end

    it "returns all evidences for members" do
      resolved_scope = described_class.new(member, Evidence.all).resolve
      expect(resolved_scope).to match_array(evidences)
    end
  end
end
