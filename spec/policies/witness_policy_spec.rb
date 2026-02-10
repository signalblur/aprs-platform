# frozen_string_literal: true

require "rails_helper"

RSpec.describe WitnessPolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:sighting) { create(:sighting, submitter: member) }
  let(:witness) { create(:witness, sighting: sighting) }

  permissions :index? do
    it "grants index access to admins" do
      expect(described_class).to permit(admin, witness)
    end

    it "grants index access to members" do
      expect(described_class).to permit(member, witness)
    end

    it "grants index access to investigators" do
      expect(described_class).to permit(investigator, witness)
    end
  end

  permissions :show? do
    it "grants show access to admins" do
      expect(described_class).to permit(admin, witness)
    end

    it "grants show access to members" do
      expect(described_class).to permit(member, witness)
    end

    it "grants show access to investigators" do
      expect(described_class).to permit(investigator, witness)
    end
  end

  permissions :create? do
    it "grants create access to admins" do
      expect(described_class).to permit(admin, Witness.new)
    end

    it "grants create access to members" do
      expect(described_class).to permit(member, Witness.new)
    end

    it "grants create access to investigators" do
      expect(described_class).to permit(investigator, Witness.new)
    end
  end

  permissions :update? do
    it "grants update access to admins" do
      expect(described_class).to permit(admin, witness)
    end

    it "grants update access to the sighting submitter" do
      expect(described_class).to permit(member, witness)
    end

    it "denies update access to non-submitter members" do
      other_member = create(:user)
      expect(described_class).not_to permit(other_member, witness)
    end

    it "denies update access to investigators who did not submit the sighting" do
      expect(described_class).not_to permit(investigator, witness)
    end

    context "with an anonymous sighting" do
      let(:anonymous_sighting) { create(:sighting, :anonymous) }
      let(:anonymous_witness) { create(:witness, sighting: anonymous_sighting) }

      it "denies update access to members for anonymous sighting witnesses" do
        expect(described_class).not_to permit(member, anonymous_witness)
      end

      it "grants update access to admins for anonymous sighting witnesses" do
        expect(described_class).to permit(admin, anonymous_witness)
      end
    end
  end

  permissions :destroy? do
    it "grants destroy access to admins" do
      expect(described_class).to permit(admin, witness)
    end

    it "denies destroy access to members" do
      expect(described_class).not_to permit(member, witness)
    end

    it "denies destroy access to investigators" do
      expect(described_class).not_to permit(investigator, witness)
    end
  end

  permissions :show_contact_info? do
    it "grants show_contact_info to admins" do
      expect(described_class).to permit(admin, witness)
    end

    it "grants show_contact_info to investigators" do
      expect(described_class).to permit(investigator, witness)
    end

    it "denies show_contact_info to members" do
      expect(described_class).not_to permit(member, witness)
    end
  end

  describe described_class::Scope do
    let!(:witnesses) { create_list(:witness, 3) }

    it "returns all witnesses for admins" do
      resolved_scope = described_class.new(admin, Witness.all).resolve
      expect(resolved_scope).to match_array(witnesses)
    end

    it "returns all witnesses for members" do
      resolved_scope = described_class.new(member, Witness.all).resolve
      expect(resolved_scope).to match_array(witnesses)
    end
  end
end
