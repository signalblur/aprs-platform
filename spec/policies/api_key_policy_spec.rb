# frozen_string_literal: true

require "rails_helper"

RSpec.describe ApiKeyPolicy do
  let(:admin) { create(:user, :admin) }
  let(:owner) { create(:user) }
  let(:other_member) { create(:user) }
  let(:api_key) { create(:api_key, user: owner) }

  permissions :index? do
    it "grants index access to key owner" do
      expect(described_class).to permit(owner, api_key)
    end

    it "grants index access to other members" do
      expect(described_class).to permit(other_member, api_key)
    end

    it "grants index access to admins" do
      expect(described_class).to permit(admin, api_key)
    end
  end

  permissions :create? do
    it "grants create access to key owner" do
      expect(described_class).to permit(owner, ApiKey.new)
    end

    it "grants create access to other members" do
      expect(described_class).to permit(other_member, ApiKey.new)
    end

    it "grants create access to admins" do
      expect(described_class).to permit(admin, ApiKey.new)
    end
  end

  permissions :show? do
    it "grants show access to key owner" do
      expect(described_class).to permit(owner, api_key)
    end

    it "denies show access to other members" do
      expect(described_class).not_to permit(other_member, api_key)
    end

    it "grants show access to admins" do
      expect(described_class).to permit(admin, api_key)
    end
  end

  permissions :destroy? do
    it "grants destroy access to key owner" do
      expect(described_class).to permit(owner, api_key)
    end

    it "denies destroy access to other members" do
      expect(described_class).not_to permit(other_member, api_key)
    end

    it "grants destroy access to admins" do
      expect(described_class).to permit(admin, api_key)
    end
  end

  describe described_class::Scope do
    let!(:owner_key) { create(:api_key, user: owner) }
    let!(:other_key) { create(:api_key, user: other_member) }

    it "returns only the user's own keys for members" do
      scope = described_class.new(owner, ApiKey.all).resolve
      expect(scope).to contain_exactly(owner_key)
    end

    it "returns all keys for admins" do
      scope = described_class.new(admin, ApiKey.all).resolve
      expect(scope).to contain_exactly(owner_key, other_key)
    end
  end
end
