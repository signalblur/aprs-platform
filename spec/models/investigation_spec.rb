# frozen_string_literal: true

require "rails_helper"

RSpec.describe Investigation, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:investigation)).to be_valid
    end

    it "has a valid with_investigator factory" do
      expect(build(:investigation, :with_investigator)).to be_valid
    end

    it "has a valid in_progress factory" do
      expect(build(:investigation, :in_progress)).to be_valid
    end

    it "has a valid closed_resolved factory" do
      expect(build(:investigation, :closed_resolved)).to be_valid
    end

    it "has a valid closed_unresolved factory" do
      expect(build(:investigation, :closed_unresolved)).to be_valid
    end

    it "has a valid closed_inconclusive factory" do
      expect(build(:investigation, :closed_inconclusive)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:assigned_investigator).class_name("User").optional }
    it { is_expected.to have_many(:sightings).dependent(:nullify) }
    it { is_expected.to have_many(:investigation_notes).dependent(:destroy) }
    it { is_expected.to have_many(:evidences).dependent(:restrict_with_error) }
  end

  describe "validations" do
    subject(:investigation) { build(:investigation) }

    it "validates case_number presence on update" do
      inv = create(:investigation)
      inv.case_number = nil
      expect(inv).not_to be_valid
      expect(inv.errors[:case_number]).to include("can't be blank")
    end

    it {
      expect(create(:investigation)).to validate_uniqueness_of(:case_number)
    }

    it { is_expected.to validate_presence_of(:title) }

    it {
      expect(investigation).to validate_length_of(:title)
        .is_at_least(5)
        .is_at_most(200)
    }

    it { is_expected.to validate_presence_of(:opened_at) }

    context "when status is closed_resolved" do
      subject(:investigation) { build(:investigation, status: :closed_resolved) }

      it "requires closed_at" do
        investigation.closed_at = nil
        investigation.classification = :identified
        expect(investigation).not_to be_valid
        expect(investigation.errors[:closed_at]).to include("is required when investigation is closed")
      end

      it "requires classification" do
        investigation.closed_at = Time.current
        investigation.classification = nil
        expect(investigation).not_to be_valid
        expect(investigation.errors[:classification]).to include("is required when investigation is closed")
      end
    end

    context "when status is closed_unresolved" do
      it "requires closed_at and classification" do
        investigation = build(:investigation, status: :closed_unresolved, closed_at: nil, classification: nil)
        expect(investigation).not_to be_valid
        expect(investigation.errors[:closed_at]).to be_present
        expect(investigation.errors[:classification]).to be_present
      end
    end

    context "when status is closed_inconclusive" do
      it "requires closed_at and classification" do
        investigation = build(:investigation, status: :closed_inconclusive, closed_at: nil, classification: nil)
        expect(investigation).not_to be_valid
        expect(investigation.errors[:closed_at]).to be_present
        expect(investigation.errors[:classification]).to be_present
      end
    end

    context "when status is open" do
      it "does not require closed_at or classification" do
        investigation = build(:investigation, status: :open, closed_at: nil, classification: nil)
        expect(investigation).to be_valid
      end
    end

    context "when assigned_investigator is a member" do
      it "is invalid" do
        member = build(:user, :member)
        investigation = build(:investigation, assigned_investigator: member)
        expect(investigation).not_to be_valid
        expect(investigation.errors[:assigned_investigator]).to include("must be an investigator or admin")
      end
    end

    context "when assigned_investigator is an investigator" do
      it "is valid" do
        investigator = build(:user, :investigator)
        expect(build(:investigation, assigned_investigator: investigator)).to be_valid
      end
    end

    context "when assigned_investigator is an admin" do
      it "is valid" do
        admin = build(:user, :admin)
        expect(build(:investigation, assigned_investigator: admin)).to be_valid
      end
    end
  end

  describe "status enum" do
    subject(:investigation) { described_class.new }

    it {
      expect(investigation).to define_enum_for(:status)
        .with_values(open: 0, in_progress: 1, closed_resolved: 2, closed_unresolved: 3, closed_inconclusive: 4)
        .with_default(:open)
    }

    it "defaults to open" do
      expect(investigation.status).to eq("open")
    end
  end

  describe "priority enum" do
    subject(:investigation) { described_class.new }

    it {
      expect(investigation).to define_enum_for(:priority)
        .with_values(low: 0, medium: 1, high: 2, critical: 3)
        .with_default(:low)
        .with_prefix(true)
    }

    it "defaults to low" do
      expect(investigation.priority).to eq("low")
    end
  end

  describe "classification enum" do
    subject(:investigation) { described_class.new }

    it {
      expect(investigation).to define_enum_for(:classification)
        .with_values(identified: 0, unidentified: 1, insufficient_data: 2, hoax: 3)
        .with_prefix(true)
    }
  end

  describe "case number generation" do
    it "auto-generates a case number on create" do
      investigation = build(:investigation, case_number: nil)
      investigation.save!
      expect(investigation.case_number).to match(/\AAPRS-\d{8}-\d{4}\z/)
    end

    it "does not overwrite an existing case number" do
      investigation = build(:investigation, case_number: "APRS-20260101-0001")
      investigation.save!
      expect(investigation.case_number).to eq("APRS-20260101-0001")
    end

    it "increments the counter for same-day cases" do
      create(:investigation, case_number: nil)
      second = build(:investigation, case_number: nil)
      second.save!
      expect(second.case_number).to match(/\AAPRS-\d{8}-0002\z/)
    end

    it "falls back to SecureRandom when all candidates collide" do
      allow(described_class).to receive(:exists?).and_return(true)
      investigation = build(:investigation, case_number: nil)
      investigation.save!
      expect(investigation.case_number).to match(/\AAPRS-\d{8}-[A-F0-9]{8}\z/)
    end
  end

  describe "#closed?" do
    it "returns true for closed_resolved" do
      expect(build(:investigation, :closed_resolved)).to be_closed
    end

    it "returns true for closed_unresolved" do
      expect(build(:investigation, :closed_unresolved)).to be_closed
    end

    it "returns true for closed_inconclusive" do
      expect(build(:investigation, :closed_inconclusive)).to be_closed
    end

    it "returns false for open" do
      expect(build(:investigation)).not_to be_closed
    end

    it "returns false for in_progress" do
      expect(build(:investigation, :in_progress)).not_to be_closed
    end
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:case_number).of_type(:string).with_options(null: false) }
    it { is_expected.to have_db_column(:title).of_type(:string).with_options(null: false) }
    it { is_expected.to have_db_column(:description).of_type(:text) }
    it { is_expected.to have_db_column(:status).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:priority).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:classification).of_type(:integer) }
    it { is_expected.to have_db_column(:findings).of_type(:text) }
    it { is_expected.to have_db_column(:assigned_investigator_id).of_type(:integer) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
    it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(null: false) }

    it "stores opened_at as timestamptz" do
      column = described_class.columns_hash["opened_at"]
      expect(column.sql_type).to eq("timestamp with time zone")
    end

    it "stores closed_at as timestamptz" do
      column = described_class.columns_hash["closed_at"]
      expect(column.sql_type).to eq("timestamp with time zone")
    end
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:case_number).unique(true) }
    it { is_expected.to have_db_index(:assigned_investigator_id) }
    it { is_expected.to have_db_index(:status) }
    it { is_expected.to have_db_index(:priority) }
  end

  describe "scopes" do
    describe ".recent" do
      it "orders by opened_at descending" do
        old = create(:investigation, opened_at: 3.days.ago)
        recent = create(:investigation, opened_at: 1.hour.ago)

        expect(described_class.recent).to eq([ recent, old ])
      end
    end

    describe ".by_status" do
      it "filters by status" do
        open_inv = create(:investigation, status: :open)
        create(:investigation, :in_progress)

        expect(described_class.by_status(:open)).to eq([ open_inv ])
      end
    end

    describe ".by_priority" do
      it "filters by priority" do
        high = create(:investigation, :high_priority)
        create(:investigation)

        expect(described_class.by_priority(:high)).to eq([ high ])
      end
    end

    describe ".assigned_to" do
      it "filters by assigned investigator" do
        investigator = create(:user, :investigator)
        assigned = create(:investigation, assigned_investigator: investigator)
        create(:investigation)

        expect(described_class.assigned_to(investigator)).to eq([ assigned ])
      end
    end

    describe ".open_cases" do
      it "returns open and in_progress investigations" do
        open_inv = create(:investigation, status: :open)
        in_progress = create(:investigation, :in_progress)
        create(:investigation, :closed_resolved)

        expect(described_class.open_cases).to contain_exactly(open_inv, in_progress)
      end
    end
  end
end
