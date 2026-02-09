# frozen_string_literal: true

require "rails_helper"

RSpec.describe UserPolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:other_user) { create(:user) }

  permissions :index? do
    it "grants access to admins" do
      expect(described_class).to permit(admin, other_user)
    end

    it "denies access to members" do
      expect(described_class).not_to permit(member, other_user)
    end

    it "denies access to investigators" do
      expect(described_class).not_to permit(investigator, other_user)
    end
  end

  permissions :show? do
    it "grants admins access to any record" do
      expect(described_class).to permit(admin, other_user)
    end

    it "grants members access to own record" do
      expect(described_class).to permit(member, member)
    end

    it "denies members access to another record" do
      expect(described_class).not_to permit(member, other_user)
    end

    it "grants investigators access to own record" do
      expect(described_class).to permit(investigator, investigator)
    end

    it "denies investigators access to another record" do
      expect(described_class).not_to permit(investigator, other_user)
    end
  end

  permissions :create?, :new? do
    it "grants creation access to admins" do
      expect(described_class).to permit(admin, other_user)
    end

    it "denies creation access to members" do
      expect(described_class).not_to permit(member, other_user)
    end

    it "denies creation access to investigators" do
      expect(described_class).not_to permit(investigator, other_user)
    end
  end

  permissions :update?, :edit? do
    it "grants admins update access to any record" do
      expect(described_class).to permit(admin, other_user)
    end

    it "grants members update access to own record" do
      expect(described_class).to permit(member, member)
    end

    it "denies members update access to another record" do
      expect(described_class).not_to permit(member, other_user)
    end

    it "grants investigators update access to own record" do
      expect(described_class).to permit(investigator, investigator)
    end

    it "denies investigators update access to another record" do
      expect(described_class).not_to permit(investigator, other_user)
    end
  end

  permissions :destroy? do
    it "grants destroy access to admins" do
      expect(described_class).to permit(admin, other_user)
    end

    it "denies destroy access to members" do
      expect(described_class).not_to permit(member, other_user)
    end

    it "denies destroy access to members even for own record" do
      expect(described_class).not_to permit(member, member)
    end

    it "denies destroy access to investigators" do
      expect(described_class).not_to permit(investigator, other_user)
    end
  end

  describe described_class::Scope do
    subject(:resolved_scope) { described_class.new(user, User.all).resolve }

    context "when user is an admin" do
      let(:user) { admin }

      it "returns all users" do
        expect(resolved_scope).to include(admin, other_user)
      end
    end

    context "when user is a member" do
      let(:user) { member }

      it "returns only the user themselves" do
        create(:user)
        expect(resolved_scope).to eq([ member ])
      end
    end
  end
end
