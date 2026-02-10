# frozen_string_literal: true

require "rails_helper"

RSpec.describe Witness, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:witness)).to be_valid
    end

    it "has a valid anonymous factory" do
      expect(build(:witness, :anonymous)).to be_valid
    end

    it "has a valid with_statement factory" do
      expect(build(:witness, :with_statement)).to be_valid
    end

    it "has a valid with_credibility_notes factory" do
      expect(build(:witness, :with_credibility_notes)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:sighting) }
  end

  describe "encryption" do
    it "encrypts contact_info in the database" do
      witness = create(:witness, contact_info: "witness@example.com")

      # Read raw value from database bypassing Active Record Encryption
      raw_value = ActiveRecord::Base.connection.select_value(
        "SELECT contact_info FROM witnesses WHERE id = #{witness.id}"
      )

      expect(raw_value).not_to eq("witness@example.com")
      expect(witness.reload.contact_info).to eq("witness@example.com")
    end

    it "allows nil contact_info" do
      witness = create(:witness, :anonymous)
      expect(witness.reload.contact_info).to be_nil
    end
  end

  describe "database columns" do
    it { is_expected.to have_db_column(:sighting_id).of_type(:integer).with_options(null: false) }
    it { is_expected.to have_db_column(:name).of_type(:string) }
    it { is_expected.to have_db_column(:contact_info).of_type(:string) }
    it { is_expected.to have_db_column(:statement).of_type(:text) }
    it { is_expected.to have_db_column(:credibility_notes).of_type(:text) }
    it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(null: false) }
    it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(null: false) }
  end

  describe "database indexes" do
    it { is_expected.to have_db_index(:sighting_id) }
  end
end
