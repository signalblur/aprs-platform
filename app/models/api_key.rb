# frozen_string_literal: true

# API key for programmatic access to the read-only REST API.
#
# Keys are generated as URL-safe base64 tokens, SHA256-digested before
# storage so that raw keys are never persisted. The raw_key is only
# available immediately after creation. Lookup uses constant-time
# digest comparison at the database level.
#
# @attr [User] user the key owner
# @attr [String] key_digest SHA256 hex digest of the raw key (unique, indexed)
# @attr [String] key_prefix first 8 characters of the raw key (for identification)
# @attr [String] name human-readable label for the key
# @attr [Boolean] active whether the key is enabled
# @attr [Time, nil] last_used_at timestamp of the most recent API request
# @attr [Time, nil] expires_at optional expiration timestamp
class ApiKey < ApplicationRecord
  belongs_to :user

  attr_accessor :raw_key

  # Clears the transient raw_key on reload since it is never persisted.
  #
  # @return [ApiKey] self
  def reload(*)
    self.raw_key = nil
    super
  end

  validates :name, presence: true
  validates :key_digest, uniqueness: true

  before_create :generate_key_and_digest

  # Returns only active keys.
  #
  # @return [ActiveRecord::Relation]
  scope :active, -> { where(active: true) }

  # Returns keys that are active and not expired.
  #
  # @return [ActiveRecord::Relation]
  scope :usable, -> { active.where("expires_at IS NULL OR expires_at > ?", Time.current) }

  # Finds an API key by its raw (unhashed) value.
  #
  # @param raw_key [String, nil] the raw API key
  # @return [ApiKey, nil] the matching key, or nil
  def self.find_by_raw_key(raw_key)
    return nil if raw_key.blank?

    digest = OpenSSL::Digest::SHA256.hexdigest(raw_key)
    find_by(key_digest: digest)
  end

  # Whether this key has passed its expiration date.
  #
  # @return [Boolean]
  def expired?
    expires_at.present? && expires_at <= Time.current
  end

  # Whether this key is active and not expired.
  #
  # @return [Boolean]
  def usable?
    active? && !expired?
  end

  # Updates last_used_at without touching updated_at or running callbacks.
  #
  # @return [void]
  def touch_last_used!
    update_column(:last_used_at, Time.current) # rubocop:disable Rails/SkipsModelValidations
  end

  private

  # Generates a cryptographically secure raw key, stores its SHA256 digest
  # and first 8 characters as a prefix for identification.
  #
  # @return [void]
  def generate_key_and_digest
    self.raw_key = SecureRandom.urlsafe_base64(32)
    self.key_digest = OpenSSL::Digest::SHA256.hexdigest(raw_key)
    self.key_prefix = raw_key[0, 8]
  end
end
