# frozen_string_literal: true

require "rails_helper"

RSpec.describe ApplicationPolicy do
  let(:user) { create(:user) }
  let(:record) { create(:user) }

  permissions :index?, :show?, :create?, :new?, :update?, :edit?, :destroy? do
    it "denies access by default" do
      expect(described_class).not_to permit(user, record)
    end
  end

  describe "delegation" do
    it "delegates new? to create?" do
      policy = described_class.new(user, record)
      # Verify new? returns the same value as create? (both false by default)
      expect(policy.new?).to eq(policy.create?)
    end

    it "delegates edit? to update?" do
      policy = described_class.new(user, record)
      # Verify edit? returns the same value as update? (both false by default)
      expect(policy.edit?).to eq(policy.update?)
    end
  end

  describe "Scope" do
    subject(:scope) { described_class::Scope.new(user, User.all) }

    it "stores user" do
      expect(scope.send(:user)).to eq(user)
    end

    it "stores scope" do
      expect(scope.send(:scope)).to eq(User.all)
    end

    it "raises NoMethodError on resolve" do
      expect { scope.resolve }.to raise_error(NoMethodError, /You must define #resolve/)
    end
  end
end
