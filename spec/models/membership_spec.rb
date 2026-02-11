# frozen_string_literal: true

require "rails_helper"

RSpec.describe Membership do
  include ActiveSupport::Testing::TimeHelpers

  describe "factory" do
    it "has a valid default factory" do
      expect(build(:membership)).to be_valid
    end

    it "has a valid professional factory" do
      expect(build(:membership, :professional)).to be_valid
    end

    it "has a valid organization factory" do
      expect(build(:membership, :organization)).to be_valid
    end

    it "has a valid with_grantor factory" do
      expect(build(:membership, :with_grantor)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:user) }
    it { is_expected.to belong_to(:granted_by).class_name("User").optional }
  end

  describe "validations" do
    it { is_expected.to validate_presence_of(:starts_at) }

    it "validates one active membership per user on create" do
      user = create(:user)
      create(:membership, user: user)
      duplicate = build(:membership, user: user)
      expect(duplicate).not_to be_valid
      expect(duplicate.errors[:user]).to include("already has an active membership")
    end

    it "allows an inactive membership when active one exists" do
      user = create(:user)
      create(:membership, user: user)
      inactive = build(:membership, user: user, active: false)
      expect(inactive).to be_valid
    end

    it "allows a new active membership when no active one exists" do
      user = create(:user)
      create(:membership, user: user, active: false)
      new_membership = build(:membership, user: user)
      expect(new_membership).to be_valid
    end
  end

  describe "tier enum" do
    it { is_expected.to define_enum_for(:tier).with_values(free: 0, professional: 1, organization: 2).with_default(:free) }

    it "defaults to free" do
      expect(described_class.new.tier).to eq("free")
    end
  end

  describe "scopes" do
    describe ".active" do
      it "returns only active memberships" do
        active = create(:membership)
        create(:membership, :inactive)
        expect(described_class.active).to contain_exactly(active)
      end
    end

    describe ".current" do
      it "returns active non-expired memberships" do
        current = create(:membership)
        create(:membership, :inactive)

        freeze_time do
          create(:membership, :expired)
          expect(described_class.current).to contain_exactly(current)
        end
      end

      it "includes memberships with no expiration" do
        membership = create(:membership, expires_at: nil)
        expect(described_class.current).to contain_exactly(membership)
      end
    end
  end

  describe "#expired?" do
    it "returns false when expires_at is nil" do
      membership = build(:membership, expires_at: nil)
      expect(membership).not_to be_expired
    end

    it "returns false when expires_at is in the future" do
      membership = build(:membership, expires_at: 1.day.from_now)
      expect(membership).not_to be_expired
    end

    it "returns true when expires_at is in the past" do
      membership = build(:membership, expires_at: 1.day.ago)
      expect(membership).to be_expired
    end
  end

  describe "#usable?" do
    it "returns true when active and not expired" do
      membership = build(:membership, active: true, expires_at: nil)
      expect(membership).to be_usable
    end

    it "returns false when inactive" do
      membership = build(:membership, active: false)
      expect(membership).not_to be_usable
    end

    it "returns false when expired" do
      membership = build(:membership, active: true, expires_at: 1.day.ago)
      expect(membership).not_to be_usable
    end

    it "returns false when both inactive and expired" do
      membership = build(:membership, active: false, expires_at: 1.day.ago)
      expect(membership).not_to be_usable
    end
  end
end
