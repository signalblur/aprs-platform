# frozen_string_literal: true

require "rails_helper"

RSpec.describe SightingPolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:sighting) { create(:sighting, submitter: member) }

  permissions :index? do
    it "grants index access to admins" do
      expect(described_class).to permit(admin, sighting)
    end

    it "grants index access to members" do
      expect(described_class).to permit(member, sighting)
    end

    it "grants index access to investigators" do
      expect(described_class).to permit(investigator, sighting)
    end
  end

  permissions :show? do
    it "grants show access to admins" do
      expect(described_class).to permit(admin, sighting)
    end

    it "grants show access to members" do
      expect(described_class).to permit(member, sighting)
    end

    it "grants show access to investigators" do
      expect(described_class).to permit(investigator, sighting)
    end
  end

  permissions :create? do
    it "grants create access to admins" do
      expect(described_class).to permit(admin, Sighting.new)
    end

    it "grants create access to members within tier limit" do
      expect(described_class).to permit(member, Sighting.new)
    end

    it "grants create access to investigators within tier limit" do
      expect(described_class).to permit(investigator, Sighting.new)
    end

    it "denies create access when monthly sighting limit is reached" do
      create_list(:sighting, 5, submitter: member)
      expect(described_class).not_to permit(member, Sighting.new)
    end

    it "grants create access when user has professional tier" do
      create(:membership, :professional, user: member)
      create_list(:sighting, 5, submitter: member)
      expect(described_class).to permit(member, Sighting.new)
    end

    it "always grants create access to admins regardless of count" do
      create_list(:sighting, 10, submitter: admin)
      expect(described_class).to permit(admin, Sighting.new)
    end
  end

  permissions :update? do
    it "grants update access to admins" do
      expect(described_class).to permit(admin, sighting)
    end

    it "grants update access to the submitter" do
      expect(described_class).to permit(member, sighting)
    end

    it "denies update access to non-submitter members" do
      other_member = create(:user)
      expect(described_class).not_to permit(other_member, sighting)
    end

    it "denies update access to anyone for anonymous sightings" do
      anonymous_sighting = create(:sighting, :anonymous)
      expect(described_class).not_to permit(member, anonymous_sighting)
    end
  end

  permissions :destroy? do
    it "grants destroy access to admins" do
      expect(described_class).to permit(admin, sighting)
    end

    it "denies destroy access to members" do
      expect(described_class).not_to permit(member, sighting)
    end

    it "denies destroy access to investigators" do
      expect(described_class).not_to permit(investigator, sighting)
    end
  end

  describe described_class::Scope do
    let!(:sightings) { create_list(:sighting, 3) }

    it "returns all sightings for admins" do
      resolved_scope = described_class.new(admin, Sighting.all).resolve
      expect(resolved_scope).to match_array(sightings)
    end

    it "returns all sightings for members" do
      resolved_scope = described_class.new(member, Sighting.all).resolve
      expect(resolved_scope).to match_array(sightings)
    end
  end
end
