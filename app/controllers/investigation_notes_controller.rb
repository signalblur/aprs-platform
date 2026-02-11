# frozen_string_literal: true

# Handles creation and deletion of investigation notes.
#
# Nested under investigations. Only assigned investigators and admins
# can create notes. Only admins can delete notes.
class InvestigationNotesController < ApplicationController
  # Override ApplicationController callbacks to scope to only the actions this controller defines.
  # Without this, Rails 7.1+ raise_on_missing_callback_actions errors because ApplicationController
  # references :index in callbacks but this controller only has :create and :destroy.
  skip_after_action :verify_policy_scoped
  after_action :verify_authorized, only: %i[create destroy]

  before_action :set_investigation

  # Creates a new note on the investigation.
  #
  # @return [void]
  def create
    @note = @investigation.investigation_notes.build(note_params)
    @note.author = current_user
    authorize @note

    if @note.save
      redirect_to @investigation, notice: "Note added."
    else
      redirect_to @investigation, alert: "Failed to add note: #{@note.errors.full_messages.join(', ')}"
    end
  end

  # Destroys a note from the investigation.
  #
  # @return [void]
  def destroy
    @note = @investigation.investigation_notes.find(params[:id])
    authorize @note
    @note.destroy!
    redirect_to @investigation, notice: "Note deleted."
  end

  private

  # Loads the parent investigation.
  #
  # @return [void]
  def set_investigation
    @investigation = Investigation.find(params[:investigation_id])
  end

  # Permitted parameters for note creation.
  #
  # @return [ActionController::Parameters]
  def note_params
    params.require(:investigation_note).permit(:content, :note_type)
  end
end
