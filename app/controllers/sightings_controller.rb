# frozen_string_literal: true

# Handles display and submission of UAP sighting reports.
#
# Provides paginated listing with filtering (status, shape, date range,
# location radius, text search), detail view with all associations,
# and create/edit forms for authenticated users. Status changes are
# restricted to admins via separate strong parameter sets.
class SightingsController < ApplicationController
  include SightingsFilterable

  before_action :set_sighting, only: %i[show edit update]

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
    authorize @sighting
    @geojson = helpers.sightings_to_geojson([ @sighting ])
  end

  # Renders the new sighting submission form.
  #
  # @return [void]
  def new
    @sighting = Sighting.new(observed_at: Time.current, observed_timezone: "America/Denver", num_witnesses: 1)
    authorize @sighting
    @shapes = Shape.order(:name)
  end

  # Creates a new sighting from submitted form data.
  #
  # @return [void]
  def create
    @sighting = Sighting.new(create_params)
    @sighting.submitter = current_user
    @sighting.location = build_location
    authorize @sighting

    if @sighting.save
      redirect_to @sighting, notice: "Sighting reported successfully."
    else
      @shapes = Shape.order(:name)
      render :new, status: :unprocessable_content
    end
  end

  # Renders the edit sighting form.
  #
  # @return [void]
  def edit
    authorize @sighting
    @shapes = Shape.order(:name)
  end

  # Updates an existing sighting.
  #
  # @return [void]
  def update
    authorize @sighting
    permitted = current_user.admin? ? admin_update_params : submitter_update_params
    @sighting.location = build_location if location_params_present?

    if @sighting.update(permitted)
      redirect_to @sighting, notice: "Sighting updated successfully."
    else
      @shapes = Shape.order(:name)
      render :edit, status: :unprocessable_content
    end
  end

  private

  # Loads the sighting with all associations for show/edit/update.
  #
  # @return [void]
  def set_sighting
    @sighting = Sighting.includes(
      :shape, :submitter, :physiological_effects, :psychological_effects,
      :equipment_effects, :environmental_traces, :evidences, :witnesses
    ).find(params[:id])
  end

  # Permitted parameters for sighting creation (no status).
  #
  # @return [ActionController::Parameters]
  def create_params
    params.require(:sighting).permit(
      :shape_id, :description, :observed_at, :observed_timezone,
      :num_witnesses, :duration_seconds, :altitude_feet,
      :visibility_conditions, :weather_notes, :media_source
    )
  end

  # Permitted parameters for submitter updates (no status change).
  #
  # @return [ActionController::Parameters]
  def submitter_update_params
    params.require(:sighting).permit(
      :shape_id, :description, :observed_at, :observed_timezone,
      :num_witnesses, :duration_seconds, :altitude_feet,
      :visibility_conditions, :weather_notes, :media_source
    )
  end

  # Permitted parameters for admin updates (includes status).
  #
  # @return [ActionController::Parameters]
  def admin_update_params
    params.require(:sighting).permit(
      :shape_id, :description, :observed_at, :observed_timezone,
      :num_witnesses, :duration_seconds, :altitude_feet,
      :visibility_conditions, :weather_notes, :media_source,
      :status
    )
  end

  # Builds a PostGIS point from latitude/longitude params.
  #
  # @return [RGeo::Geographic::SphericalPointImpl, nil]
  def build_location
    lat = params.dig(:sighting, :latitude)
    lng = params.dig(:sighting, :longitude)
    return nil if lat.blank? || lng.blank?

    RGeo::Geographic.spherical_factory(srid: 4326).point(lng.to_f, lat.to_f)
  end

  # Checks if location params are present in the request.
  #
  # @return [Boolean]
  def location_params_present?
    params.dig(:sighting, :latitude).present? || params.dig(:sighting, :longitude).present?
  end
end
