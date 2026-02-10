# frozen_string_literal: true

require "rails_helper"

RSpec.describe ApiKey, type: :model do
  describe "factory" do
    it "has a valid default factory" do
      expect(build(:api_key)).to be_valid
    end

    it "has a valid inactive factory" do
      expect(build(:api_key, :inactive)).to be_valid
    end

    it "has a valid expired factory" do
      expect(build(:api_key, :expired)).to be_valid
    end

    it "has a valid with_expiration factory" do
      expect(build(:api_key, :with_expiration)).to be_valid
    end
  end

  describe "associations" do
    it { is_expected.to belong_to(:user) }
  end

  describe "validations" do
    subject(:api_key) { build(:api_key) }

    it { is_expected.to validate_presence_of(:name) }

    it "validates uniqueness of key_digest" do
      create(:api_key)
      expect(api_key).to validate_uniqueness_of(:key_digest)
    end
  end

  describe "key generation" do
    it "generates raw_key on create" do
      api_key = create(:api_key)
      expect(api_key.raw_key).to be_present
    end

    it "generates a key_digest on create" do
      api_key = create(:api_key)
      expect(api_key.key_digest).to be_present
    end

    it "generates a key_prefix on create" do
      api_key = create(:api_key)
      expect(api_key.key_prefix).to be_present
      expect(api_key.key_prefix.length).to eq(8)
    end

    it "sets key_prefix from the beginning of raw_key" do
      api_key = create(:api_key)
      expect(api_key.raw_key).to start_with(api_key.key_prefix)
    end

    it "digests the raw key with SHA256" do
      api_key = create(:api_key)
      expected_digest = OpenSSL::Digest::SHA256.hexdigest(api_key.raw_key)
      expect(api_key.key_digest).to eq(expected_digest)
    end

    it "generates unique keys for different instances" do
      key1 = create(:api_key)
      key2 = create(:api_key)
      expect(key1.key_digest).not_to eq(key2.key_digest)
    end

    it "does not expose raw_key after reload" do
      api_key = create(:api_key)
      api_key.reload
      expect(api_key.raw_key).to be_nil
    end
  end

  describe ".find_by_raw_key" do
    it "returns the api key when given a valid raw key" do
      api_key = create(:api_key)
      raw = api_key.raw_key
      expect(described_class.find_by_raw_key(raw)).to eq(api_key)
    end

    it "returns nil when given an invalid raw key" do
      expect(described_class.find_by_raw_key("invalid_key")).to be_nil
    end

    it "returns nil when given nil" do
      expect(described_class.find_by_raw_key(nil)).to be_nil
    end

    it "returns nil when given an empty string" do
      expect(described_class.find_by_raw_key("")).to be_nil
    end
  end

  describe "scopes" do
    describe ".active" do
      it "returns only active keys" do
        active_key = create(:api_key)
        create(:api_key, :inactive)
        expect(described_class.active).to eq([ active_key ])
      end
    end

    describe ".usable" do
      it "returns active non-expired keys" do
        usable = create(:api_key)
        create(:api_key, :inactive)
        create(:api_key, :expired)
        expect(described_class.usable).to eq([ usable ])
      end

      it "includes active keys with future expiration" do
        key = create(:api_key, :with_expiration)
        expect(described_class.usable).to include(key)
      end

      it "includes active keys with no expiration" do
        key = create(:api_key, expires_at: nil)
        expect(described_class.usable).to include(key)
      end
    end
  end

  describe "#expired?" do
    it "returns false when expires_at is nil" do
      api_key = build(:api_key, expires_at: nil)
      expect(api_key).not_to be_expired
    end

    it "returns false when expires_at is in the future" do
      api_key = build(:api_key, expires_at: 1.day.from_now)
      expect(api_key).not_to be_expired
    end

    it "returns true when expires_at is in the past" do
      api_key = build(:api_key, :expired)
      expect(api_key).to be_expired
    end
  end

  describe "#usable?" do
    it "returns true when active and not expired" do
      api_key = build(:api_key)
      expect(api_key).to be_usable
    end

    it "returns false when inactive" do
      api_key = build(:api_key, :inactive)
      expect(api_key).not_to be_usable
    end

    it "returns false when expired" do
      api_key = build(:api_key, :expired)
      expect(api_key).not_to be_usable
    end

    it "returns false when both inactive and expired" do
      api_key = build(:api_key, :inactive, :expired)
      expect(api_key).not_to be_usable
    end
  end

  describe "#touch_last_used!" do
    include ActiveSupport::Testing::TimeHelpers

    it "updates last_used_at without callbacks" do
      api_key = create(:api_key)
      expect(api_key.last_used_at).to be_nil

      freeze_time do
        api_key.touch_last_used!
        expect(api_key.reload.last_used_at).to be_within(1.second).of(Time.current)
      end
    end

    it "does not change updated_at" do
      api_key = create(:api_key)
      original_updated_at = api_key.updated_at

      travel_to 1.minute.from_now do
        api_key.touch_last_used!
        expect(api_key.reload.updated_at).to eq(original_updated_at)
      end
    end
  end
end
