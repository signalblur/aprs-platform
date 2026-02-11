# frozen_string_literal: true

require "rails_helper"

RSpec.describe TierLimits do
  describe "#tier" do
    it "returns 'free' when no membership exists" do
      user = create(:user)
      expect(user.tier).to eq("free")
    end

    it "returns the active membership tier" do
      user = create(:user)
      create(:membership, :professional, user: user)
      expect(user.tier).to eq("professional")
    end

    it "returns 'free' when active membership is expired" do
      user = create(:user)
      create(:membership, :professional, user: user, expires_at: 1.day.ago)
      expect(user.tier).to eq("free")
    end

    it "returns 'free' when membership is inactive" do
      user = create(:user)
      create(:membership, :professional, :inactive, user: user)
      expect(user.tier).to eq("free")
    end

    it "returns the tier when membership has no expiration" do
      user = create(:user)
      create(:membership, :organization, user: user, expires_at: nil)
      expect(user.tier).to eq("organization")
    end
  end

  describe "#professional_or_above?" do
    it "returns false for free tier" do
      user = create(:user)
      expect(user).not_to be_professional_or_above
    end

    it "returns true for professional tier" do
      user = create(:user)
      create(:membership, :professional, user: user)
      expect(user).to be_professional_or_above
    end

    it "returns true for organization tier" do
      user = create(:user)
      create(:membership, :organization, user: user)
      expect(user).to be_professional_or_above
    end
  end

  describe "#organization?" do
    it "returns false for free tier" do
      user = create(:user)
      expect(user).not_to be_organization
    end

    it "returns false for professional tier" do
      user = create(:user)
      create(:membership, :professional, user: user)
      expect(user).not_to be_organization
    end

    it "returns true for organization tier" do
      user = create(:user)
      create(:membership, :organization, user: user)
      expect(user).to be_organization
    end
  end

  describe "#tier_limit" do
    it "returns free tier limits by default" do
      user = create(:user)
      expect(user.tier_limit(:sightings_per_month)).to eq(5)
      expect(user.tier_limit(:evidence_per_sighting)).to eq(3)
      expect(user.tier_limit(:evidence_max_size_mb)).to eq(50)
      expect(user.tier_limit(:api_keys)).to eq(1)
    end

    it "returns professional tier limits" do
      user = create(:user)
      create(:membership, :professional, user: user)
      expect(user.tier_limit(:sightings_per_month)).to eq(50)
      expect(user.tier_limit(:evidence_per_sighting)).to eq(10)
      expect(user.tier_limit(:api_keys)).to eq(5)
    end

    it "returns nil for unlimited organization sightings" do
      user = create(:user)
      create(:membership, :organization, user: user)
      expect(user.tier_limit(:sightings_per_month)).to be_nil
    end
  end

  describe "#within_tier_limit?" do
    it "returns true when count is below limit" do
      user = create(:user)
      expect(user.within_tier_limit?(:sightings_per_month, 3)).to be true
    end

    it "returns false when count equals limit" do
      user = create(:user)
      expect(user.within_tier_limit?(:sightings_per_month, 5)).to be false
    end

    it "returns false when count exceeds limit" do
      user = create(:user)
      expect(user.within_tier_limit?(:sightings_per_month, 10)).to be false
    end

    it "returns true for unlimited limits (nil)" do
      user = create(:user)
      create(:membership, :organization, user: user)
      expect(user.within_tier_limit?(:sightings_per_month, 9999)).to be true
    end

    it "always returns true for admins regardless of count" do
      admin = create(:user, :admin)
      expect(admin.within_tier_limit?(:sightings_per_month, 9999)).to be true
    end
  end
end
