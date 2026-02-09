# frozen_string_literal: true

require "rails_helper"

RSpec.describe User, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:user)).to be_valid
    end

    it "has a valid admin factory" do
      expect(build(:user, :admin)).to be_valid
    end

    it "has a valid investigator factory" do
      expect(build(:user, :investigator)).to be_valid
    end
  end

  describe "Devise modules" do
    it "includes database_authenticatable" do
      expect(described_class.devise_modules).to include(:database_authenticatable)
    end

    it "includes registerable" do
      expect(described_class.devise_modules).to include(:registerable)
    end

    it "includes recoverable" do
      expect(described_class.devise_modules).to include(:recoverable)
    end

    it "includes rememberable" do
      expect(described_class.devise_modules).to include(:rememberable)
    end

    it "includes validatable" do
      expect(described_class.devise_modules).to include(:validatable)
    end

    it "includes trackable" do
      expect(described_class.devise_modules).to include(:trackable)
    end

    it "includes lockable" do
      expect(described_class.devise_modules).to include(:lockable)
    end

    it "includes confirmable" do
      expect(described_class.devise_modules).to include(:confirmable)
    end
  end

  describe "role enum" do
    it { is_expected.to define_enum_for(:role).with_values(member: 0, investigator: 1, admin: 2).with_default(:member) }

    it "defaults to member" do
      expect(described_class.new.role).to eq("member")
    end

    it "validates role inclusion" do
      user = build(:user, role: :admin)
      expect(user).to be_valid
    end
  end
end
