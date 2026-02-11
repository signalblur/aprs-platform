# frozen_string_literal: true

# Manages evidence file uploads nested under sightings.
#
# Users can upload evidence files to sightings they have access to,
# subject to tier-based limits. Only admins can delete evidence.
class EvidencesController < ApplicationController
  skip_after_action :verify_policy_scoped
  skip_after_action :verify_authorized
  after_action :verify_authorized, only: %i[create destroy]
  before_action :set_sighting

  # Uploads a new evidence file to the sighting.
  #
  # @return [void]
  def create
    @evidence = @sighting.evidences.new(evidence_params)
    @evidence.submitted_by = current_user
    authorize @evidence

    if @evidence.save
      redirect_to sighting_path(@sighting), notice: "Evidence uploaded successfully."
    else
      redirect_to sighting_path(@sighting), alert: @evidence.errors.full_messages.to_sentence
    end
  end

  # Destroys an evidence record and its attached file.
  #
  # @return [void]
  def destroy
    @evidence = @sighting.evidences.find(params[:id])
    authorize @evidence
    @evidence.destroy!
    redirect_to sighting_path(@sighting), notice: "Evidence removed."
  end

  private

  # Loads the parent sighting.
  #
  # @return [void]
  def set_sighting
    @sighting = Sighting.find(params[:sighting_id])
  end

  # Permitted parameters for evidence creation.
  #
  # @return [ActionController::Parameters]
  def evidence_params
    params.require(:evidence).permit(:evidence_type, :description, :file)
  end
end
