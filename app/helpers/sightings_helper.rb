# frozen_string_literal: true

# View helpers for sighting display pages.
module SightingsHelper
  # Converts a collection of sightings to a GeoJSON FeatureCollection string.
  #
  # Filters out sightings without a location. Each feature includes the
  # sighting's coordinates, shape name, status, and a popup HTML string
  # with truncated, HTML-escaped description.
  #
  # @param sightings [ActiveRecord::Relation] sightings to convert (should include :shape)
  # @return [String] GeoJSON FeatureCollection as a JSON string
  def sightings_to_geojson(sightings)
    features = sightings.select(&:location).map { |s| sighting_to_feature(s) }

    {
      type: "FeatureCollection",
      features: features
    }.to_json
  end

  private

  # Builds a GeoJSON Feature hash for a single sighting.
  #
  # @param sighting [Sighting] the sighting to convert
  # @return [Hash] GeoJSON Feature
  def sighting_to_feature(sighting)
    {
      type: "Feature",
      geometry: {
        type: "Point",
        coordinates: [ sighting.location.x, sighting.location.y ]
      },
      properties: {
        id: sighting.id,
        shape: sighting.shape.name,
        status: sighting.status,
        popup: sighting_popup_html(sighting)
      }
    }
  end

  # Generates HTML-safe popup content for a sighting map marker.
  #
  # @param sighting [Sighting] the sighting to render
  # @return [String] HTML string for the Leaflet popup
  def sighting_popup_html(sighting)
    shape = ERB::Util.html_escape(sighting.shape.name)
    desc = ERB::Util.html_escape(sighting.description.truncate(100))

    "<strong>#{shape}</strong><br>#{desc}"
  end
end
