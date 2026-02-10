# frozen_string_literal: true

# Handles display of UAP sighting reports.
#
# Provides paginated listing with filtering (status, shape, date range,
# location radius, text search) and detail view with all associations.
# All actions require authentication and use Pundit authorization.
class SightingsController < ApplicationController
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

  private

  # Applies all active filters to the sighting query.
  #
  # @param scope [ActiveRecord::Relation] the base scope
  # @return [ActiveRecord::Relation] the filtered scope
  def apply_filters(scope)
    scope = scope.by_status(params[:status]) if params[:status].present?
    scope = scope.by_shape(params[:shape_id]) if params[:shape_id].present?
    scope = scope.search_description(params[:q]) if params[:q].present?
    scope = apply_date_filter(scope)
    scope = apply_location_filter(scope)
    scope
  end

  # Applies date range filter when both bounds are present.
  #
  # @param scope [ActiveRecord::Relation] the current scope
  # @return [ActiveRecord::Relation] the filtered scope
  def apply_date_filter(scope)
    return scope unless params[:date_from].present? && params[:date_to].present?

    from = Date.parse(params[:date_from]).beginning_of_day
    to = Date.parse(params[:date_to]).end_of_day
    scope.observed_between(from, to)
  end

  # Applies geographic radius filter when all location params are present.
  #
  # @param scope [ActiveRecord::Relation] the current scope
  # @return [ActiveRecord::Relation] the filtered scope
  def apply_location_filter(scope)
    return scope unless params[:lat].present? && params[:lng].present? && params[:radius].present?

    scope.within_radius(params[:lat].to_f, params[:lng].to_f, params[:radius].to_f)
  end
end
