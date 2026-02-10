# frozen_string_literal: true

# Core data model representing a single UAP observation report.
#
# Stores geospatial location (PostGIS geography), temporal data with
# timezone awareness, shape classification, and a status workflow enum.
# This is the foundation that all subsequent phases build on (effects,
# evidence, witnesses, investigations, API).
#
# @attr [User, nil] submitter the user who submitted the sighting (nil for anonymous)
# @attr [Shape] shape the shape category selected by the observer
# @attr [String] description free-text description of the sighting (20-10,000 chars)
# @attr [Integer, nil] duration_seconds estimated duration of the observation
# @attr [RGeo::Geographic::SphericalPointImpl, nil] location PostGIS geography point (SRID 4326)
# @attr [BigDecimal, nil] altitude_feet estimated altitude in feet
# @attr [Time] observed_at when the sighting was observed (stored as timestamptz)
# @attr [String] observed_timezone IANA timezone of the observer
# @attr [Integer] num_witnesses number of witnesses present (minimum 1)
# @attr [String, nil] visibility_conditions description of visibility conditions
# @attr [String, nil] weather_notes weather observations at the time
# @attr [String, nil] media_source source of any media captured
# @attr [Integer] status workflow status (submitted, under_review, verified, rejected)
class Sighting < ApplicationRecord
  belongs_to :submitter, class_name: "User", optional: true, inverse_of: :sightings
  belongs_to :shape

  has_many :physiological_effects, dependent: :destroy
  has_many :psychological_effects, dependent: :destroy
  has_many :equipment_effects, dependent: :destroy
  has_many :environmental_traces, dependent: :destroy

  enum :status, { submitted: 0, under_review: 1, verified: 2, rejected: 3 }, default: :submitted, validate: true

  validates :description, presence: true, length: { minimum: 20, maximum: 10_000 }
  validates :observed_at, presence: true
  validates :observed_timezone, presence: true, inclusion: { in: ActiveSupport::TimeZone::MAPPING.values }
  validates :num_witnesses, numericality: { greater_than_or_equal_to: 1, only_integer: true }
  validates :duration_seconds, numericality: { greater_than: 0, only_integer: true }, allow_nil: true

  # Orders sightings by most recently observed first.
  #
  # @return [ActiveRecord::Relation] sightings ordered by observed_at DESC
  scope :recent, -> { order(observed_at: :desc) }

  # Filters sightings by workflow status.
  #
  # @param status [Symbol, String, Integer] the status to filter by
  # @return [ActiveRecord::Relation] sightings matching the given status
  scope :by_status, ->(status) { where(status: status) }

  # Filters sightings by shape classification.
  #
  # @param shape_id [Integer] the shape ID to filter by
  # @return [ActiveRecord::Relation] sightings with the given shape
  scope :by_shape, ->(shape_id) { where(shape_id: shape_id) }

  # Filters sightings observed within a date range.
  #
  # @param start_time [Time] the start of the range (inclusive)
  # @param end_time [Time] the end of the range (inclusive)
  # @return [ActiveRecord::Relation] sightings within the date range
  scope :observed_between, ->(start_time, end_time) { where(observed_at: start_time..end_time) }

  # Filters sightings within a geographic radius using PostGIS ST_DWithin.
  #
  # @param lat [Float] latitude of the center point
  # @param lng [Float] longitude of the center point
  # @param meters [Numeric] radius in meters
  # @return [ActiveRecord::Relation] sightings within the radius
  scope :within_radius, ->(lat, lng, meters) {
    where(
      "ST_DWithin(location, ST_SetSRID(ST_MakePoint(?, ?), 4326)::geography, ?)",
      lng, lat, meters
    )
  }
end
