# frozen_string_literal: true

# Handles display of UAP sighting reports.
#
# Provides paginated listing with filtering (status, shape, date range,
# location radius, text search) and detail view with all associations.
# All actions require authentication and use Pundit authorization.
class SightingsController < ApplicationController
  include SightingsFilterable

  # Lists sightings with optional filters, pagination, and map GeoJSON.
  #
  # @return [void]
  def index
    sightings = policy_scope(Sighting).includes(:shape, :submitter).recent
    sightings = apply_filters(sightings)
    @pagy, @sightings = pagy(sightings)
    @shapes = Shape.order(:name)
    @geojson = helpers.sightings_to_geojson(@sightings)
  end

  # Displays a single sighting with all associated records.
  #
  # @return [void]
  def show
    @sighting = Sighting.includes(
      :shape, :submitter, :physiological_effects, :psychological_effects,
      :equipment_effects, :environmental_traces, :evidences, :witnesses
    ).find(params[:id])
    authorize @sighting
    @geojson = helpers.sightings_to_geojson([ @sighting ])
  end
end
