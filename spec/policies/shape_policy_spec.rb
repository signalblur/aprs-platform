# frozen_string_literal: true

require "rails_helper"

RSpec.describe ShapePolicy do
  let(:admin) { create(:user, :admin) }
  let(:member) { create(:user) }
  let(:investigator) { create(:user, :investigator) }
  let(:shape) { create(:shape) }

  permissions :index? do
    it "grants index access to admins" do
      expect(described_class).to permit(admin, shape)
    end

    it "grants index access to members" do
      expect(described_class).to permit(member, shape)
    end

    it "grants index access to investigators" do
      expect(described_class).to permit(investigator, shape)
    end
  end

  permissions :show? do
    it "grants show access to admins" do
      expect(described_class).to permit(admin, shape)
    end

    it "grants show access to members" do
      expect(described_class).to permit(member, shape)
    end

    it "grants show access to investigators" do
      expect(described_class).to permit(investigator, shape)
    end
  end

  permissions :create?, :new? do
    it "grants creation access to admins" do
      expect(described_class).to permit(admin, shape)
    end

    it "denies creation access to members" do
      expect(described_class).not_to permit(member, shape)
    end

    it "denies creation access to investigators" do
      expect(described_class).not_to permit(investigator, shape)
    end
  end

  permissions :update?, :edit? do
    it "grants update access to admins" do
      expect(described_class).to permit(admin, shape)
    end

    it "denies update access to members" do
      expect(described_class).not_to permit(member, shape)
    end

    it "denies update access to investigators" do
      expect(described_class).not_to permit(investigator, shape)
    end
  end

  permissions :destroy? do
    it "grants destroy access to admins" do
      expect(described_class).to permit(admin, shape)
    end

    it "denies destroy access to members" do
      expect(described_class).not_to permit(member, shape)
    end

    it "denies destroy access to investigators" do
      expect(described_class).not_to permit(investigator, shape)
    end
  end

  describe described_class::Scope do
    let!(:shapes) { create_list(:shape, 3) }

    it "returns all shapes for admins" do
      resolved_scope = described_class.new(admin, Shape.all).resolve
      expect(resolved_scope).to match_array(shapes)
    end

    it "returns all shapes for members" do
      resolved_scope = described_class.new(member, Shape.all).resolve
      expect(resolved_scope).to match_array(shapes)
    end
  end
end
