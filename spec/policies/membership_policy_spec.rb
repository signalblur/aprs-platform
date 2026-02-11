# frozen_string_literal: true

require "rails_helper"

RSpec.describe MembershipPolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:membership) { create(:membership, user: member) }

  permissions :index? do
    it "grants index access to admins" do
      expect(described_class).to permit(admin, Membership)
    end

    it "denies index access to members" do
      expect(described_class).not_to permit(member, Membership)
    end

    it "denies index access to investigators" do
      expect(described_class).not_to permit(investigator, Membership)
    end
  end

  permissions :show? do
    it "grants show access to admins" do
      expect(described_class).to permit(admin, membership)
    end

    it "grants show access to the membership owner" do
      expect(described_class).to permit(member, membership)
    end

    it "denies show access to other members" do
      other = create(:user)
      expect(described_class).not_to permit(other, membership)
    end

    it "denies show access to investigators who are not the owner" do
      expect(described_class).not_to permit(investigator, membership)
    end
  end

  permissions :create? do
    it "grants create access to admins" do
      expect(described_class).to permit(admin, Membership.new)
    end

    it "denies create access to members" do
      expect(described_class).not_to permit(member, Membership.new)
    end

    it "denies create access to investigators" do
      expect(described_class).not_to permit(investigator, Membership.new)
    end
  end

  permissions :update? do
    it "grants update access to admins" do
      expect(described_class).to permit(admin, membership)
    end

    it "denies update access to the membership owner" do
      expect(described_class).not_to permit(member, membership)
    end

    it "denies update access to investigators" do
      expect(described_class).not_to permit(investigator, membership)
    end
  end

  permissions :destroy? do
    it "denies destroy access to admins" do
      expect(described_class).not_to permit(admin, membership)
    end

    it "denies destroy access to members" do
      expect(described_class).not_to permit(member, membership)
    end

    it "denies destroy access to investigators" do
      expect(described_class).not_to permit(investigator, membership)
    end
  end

  describe described_class::Scope do
    let!(:member_membership) { create(:membership, user: member) }
    let!(:other_membership) { create(:membership) }

    it "returns all memberships for admins" do
      scope = described_class.new(admin, Membership.all).resolve
      expect(scope).to contain_exactly(member_membership, other_membership)
    end

    it "returns only the user's own memberships for members" do
      scope = described_class.new(member, Membership.all).resolve
      expect(scope).to contain_exactly(member_membership)
    end

    it "returns only the user's own memberships for investigators" do
      scope = described_class.new(investigator, Membership.all).resolve
      expect(scope).to be_empty
    end
  end
end
