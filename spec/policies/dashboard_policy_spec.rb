# frozen_string_literal: true

require "rails_helper"

RSpec.describe DashboardPolicy do
  subject(:policy) { described_class.new(user, :dashboard) }

  describe "#index?" do
    context "when user is admin" do
      let(:user) { build(:user, :admin) }

      it "permits access" do
        expect(policy).to be_index
      end
    end

    context "when user is investigator" do
      let(:user) { build(:user, :investigator) }

      it "denies access" do
        expect(policy).not_to be_index
      end
    end

    context "when user is member" do
      let(:user) { build(:user) }

      it "denies access" do
        expect(policy).not_to be_index
      end
    end
  end
end
