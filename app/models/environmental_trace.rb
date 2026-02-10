# frozen_string_literal: true

# Tracks physical traces or environmental changes observed at a UAP sighting location.
#
# Records trace type, optional precise location (PostGIS geography), and
# optional scientific measurements (value + unit). Location defaults to the
# parent sighting's location if not specified.
#
# @attr [Sighting] sighting the parent sighting report
# @attr [String] trace_type the category of trace (e.g., "ground_marking", "radiation")
# @attr [String, nil] description detailed description of the trace
# @attr [RGeo::Geographic::SphericalPointImpl, nil] location PostGIS geography point (SRID 4326)
# @attr [String, nil] measured_value measurement reading if applicable
# @attr [String, nil] measurement_unit unit of measurement (e.g., "mSv/hr", "meters")
class EnvironmentalTrace < ApplicationRecord
  belongs_to :sighting

  validates :trace_type, presence: true
  validates :measurement_unit, presence: true, if: -> { measured_value.present? }
end
