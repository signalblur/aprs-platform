# frozen_string_literal: true

module Api
  module V1
    # Serializes Sighting records for list/index responses.
    #
    # Includes core fields, shape as nested hash, submitter email,
    # and location as lat/lng hash. All timestamps are ISO 8601.
    class SightingSerializer
      # @param sighting [Sighting] the sighting to serialize
      def initialize(sighting)
        @sighting = sighting
      end

      # @return [Hash] JSON-compatible hash representation
      def as_json
        {
          id: @sighting.id,
          description: @sighting.description,
          status: @sighting.status,
          shape: shape_hash,
          submitter_email: @sighting.submitter&.email,
          location: location_hash,
          altitude_feet: @sighting.altitude_feet&.to_f,
          duration_seconds: @sighting.duration_seconds,
          num_witnesses: @sighting.num_witnesses,
          visibility_conditions: @sighting.visibility_conditions,
          weather_notes: @sighting.weather_notes,
          media_source: @sighting.media_source,
          observed_at: @sighting.observed_at.iso8601,
          observed_timezone: @sighting.observed_timezone,
          created_at: @sighting.created_at.iso8601,
          updated_at: @sighting.updated_at.iso8601
        }
      end

      private

      # @return [Hash] shape as {id, name}
      def shape_hash
        { id: @sighting.shape.id, name: @sighting.shape.name }
      end

      # @return [Hash, nil] location as {lat, lng} or nil
      def location_hash
        return nil unless @sighting.location

        { lat: @sighting.location.latitude, lng: @sighting.location.longitude }
      end
    end
  end
end
