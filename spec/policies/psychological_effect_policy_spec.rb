# frozen_string_literal: true

require "rails_helper"

RSpec.describe PsychologicalEffectPolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:sighting) { create(:sighting, submitter: member) }
  let(:effect) { create(:psychological_effect, sighting: sighting) }

  permissions :index? do
    it "grants index access to admins" do
      expect(described_class).to permit(admin, effect)
    end

    it "grants index access to members" do
      expect(described_class).to permit(member, effect)
    end

    it "grants index access to investigators" do
      expect(described_class).to permit(investigator, effect)
    end
  end

  permissions :show? do
    it "grants show access to admins" do
      expect(described_class).to permit(admin, effect)
    end

    it "grants show access to members" do
      expect(described_class).to permit(member, effect)
    end

    it "grants show access to investigators" do
      expect(described_class).to permit(investigator, effect)
    end
  end

  permissions :create? do
    it "grants create access to admins" do
      expect(described_class).to permit(admin, PsychologicalEffect.new)
    end

    it "grants create access to members" do
      expect(described_class).to permit(member, PsychologicalEffect.new)
    end

    it "grants create access to investigators" do
      expect(described_class).to permit(investigator, PsychologicalEffect.new)
    end
  end

  permissions :update? do
    it "grants update access to admins" do
      expect(described_class).to permit(admin, effect)
    end

    it "grants update access to the sighting submitter" do
      expect(described_class).to permit(member, effect)
    end

    it "denies update access to non-submitter members" do
      other_member = create(:user)
      expect(described_class).not_to permit(other_member, effect)
    end
  end

  permissions :destroy? do
    it "grants destroy access to admins" do
      expect(described_class).to permit(admin, effect)
    end

    it "denies destroy access to members" do
      expect(described_class).not_to permit(member, effect)
    end

    it "denies destroy access to investigators" do
      expect(described_class).not_to permit(investigator, effect)
    end
  end

  describe described_class::Scope do
    let!(:effects) { create_list(:psychological_effect, 3) }

    it "returns all effects for admins" do
      resolved_scope = described_class.new(admin, PsychologicalEffect.all).resolve
      expect(resolved_scope).to match_array(effects)
    end

    it "returns all effects for members" do
      resolved_scope = described_class.new(member, PsychologicalEffect.all).resolve
      expect(resolved_scope).to match_array(effects)
    end
  end
end
