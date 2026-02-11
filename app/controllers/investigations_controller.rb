# frozen_string_literal: true

# Manages investigation CRUD, sighting linking, and case management.
#
# Provides paginated listing with filters, detail view with associated
# sightings and notes, and admin/investigator-gated create/update/destroy.
class InvestigationsController < ApplicationController
  before_action :set_investigation, only: %i[show edit update destroy link_sighting unlink_sighting]

  # Lists investigations with optional filters and pagination.
  #
  # @return [void]
  def index
    investigations = policy_scope(Investigation).includes(:assigned_investigator).recent
    investigations = apply_filters(investigations)
    @pagy, @investigations = pagy(investigations)
  end

  # Displays an investigation with linked sightings and notes.
  #
  # @return [void]
  def show
    authorize @investigation
  end

  # Renders the new investigation form.
  #
  # @return [void]
  def new
    @investigation = Investigation.new(opened_at: Time.current)
    authorize @investigation
  end

  # Creates a new investigation.
  #
  # @return [void]
  def create
    @investigation = Investigation.new(investigation_params)
    authorize @investigation

    if @investigation.save
      redirect_to @investigation, notice: "Investigation created successfully."
    else
      render :new, status: :unprocessable_content
    end
  end

  # Renders the edit investigation form.
  #
  # @return [void]
  def edit
    authorize @investigation
  end

  # Updates an existing investigation.
  #
  # @return [void]
  def update
    authorize @investigation

    if @investigation.update(investigation_params)
      redirect_to @investigation, notice: "Investigation updated successfully."
    else
      render :edit, status: :unprocessable_content
    end
  end

  # Destroys an investigation.
  #
  # @return [void]
  def destroy
    authorize @investigation
    @investigation.destroy!
    redirect_to investigations_path, notice: "Investigation deleted."
  end

  # Links a sighting to this investigation.
  #
  # @return [void]
  def link_sighting
    authorize @investigation
    sighting = Sighting.find(params[:sighting_id])
    sighting.update!(investigation: @investigation)
    redirect_to @investigation, notice: "Sighting linked successfully."
  end

  # Unlinks a sighting from this investigation.
  #
  # @return [void]
  def unlink_sighting
    authorize @investigation
    sighting = @investigation.sightings.find(params[:sighting_id])
    sighting.update!(investigation: nil)
    redirect_to @investigation, notice: "Sighting unlinked."
  end

  private

  # Loads the investigation by ID.
  #
  # @return [void]
  def set_investigation
    @investigation = Investigation.find(params[:id])
  end

  # Permitted parameters for investigation create/update.
  #
  # @return [ActionController::Parameters]
  def investigation_params
    params.require(:investigation).permit(
      :title, :description, :status, :priority, :classification,
      :findings, :assigned_investigator_id, :opened_at, :closed_at
    )
  end

  # Applies query filters from params to the investigation relation.
  #
  # @param scope [ActiveRecord::Relation]
  # @return [ActiveRecord::Relation]
  def apply_filters(scope)
    scope = scope.by_status(params[:status]) if params[:status].present?
    scope = scope.by_priority(params[:priority]) if params[:priority].present?
    scope = scope.assigned_to(params[:assigned_to]) if params[:assigned_to].present?
    scope
  end
end
