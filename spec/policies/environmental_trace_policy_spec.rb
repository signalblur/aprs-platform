# frozen_string_literal: true

require "rails_helper"

RSpec.describe EnvironmentalTracePolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:sighting) { create(:sighting, submitter: member) }
  let(:trace) { create(:environmental_trace, sighting: sighting) }

  permissions :index? do
    it "grants index access to admins" do
      expect(described_class).to permit(admin, trace)
    end

    it "grants index access to members" do
      expect(described_class).to permit(member, trace)
    end

    it "grants index access to investigators" do
      expect(described_class).to permit(investigator, trace)
    end
  end

  permissions :show? do
    it "grants show access to admins" do
      expect(described_class).to permit(admin, trace)
    end

    it "grants show access to members" do
      expect(described_class).to permit(member, trace)
    end

    it "grants show access to investigators" do
      expect(described_class).to permit(investigator, trace)
    end
  end

  permissions :create? do
    it "grants create access to admins" do
      expect(described_class).to permit(admin, EnvironmentalTrace.new)
    end

    it "grants create access to members" do
      expect(described_class).to permit(member, EnvironmentalTrace.new)
    end

    it "grants create access to investigators" do
      expect(described_class).to permit(investigator, EnvironmentalTrace.new)
    end
  end

  permissions :update? do
    it "grants update access to admins" do
      expect(described_class).to permit(admin, trace)
    end

    it "grants update access to the sighting submitter" do
      expect(described_class).to permit(member, trace)
    end

    it "denies update access to non-submitter members" do
      other_member = create(:user)
      expect(described_class).not_to permit(other_member, trace)
    end
  end

  permissions :destroy? do
    it "grants destroy access to admins" do
      expect(described_class).to permit(admin, trace)
    end

    it "denies destroy access to members" do
      expect(described_class).not_to permit(member, trace)
    end

    it "denies destroy access to investigators" do
      expect(described_class).not_to permit(investigator, trace)
    end
  end

  describe described_class::Scope do
    let!(:traces) { create_list(:environmental_trace, 3) }

    it "returns all traces for admins" do
      resolved_scope = described_class.new(admin, EnvironmentalTrace.all).resolve
      expect(resolved_scope).to match_array(traces)
    end

    it "returns all traces for members" do
      resolved_scope = described_class.new(member, EnvironmentalTrace.all).resolve
      expect(resolved_scope).to match_array(traces)
    end
  end
end
