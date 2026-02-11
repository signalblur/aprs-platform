# frozen_string_literal: true

module Api
  module V1
    # Read-only API endpoints for investigation cases.
    #
    # Provides paginated listing with filters and detail views.
    # Findings and notes are gated by role (investigator/admin only).
    class InvestigationsController < BaseController
      # Lists investigations with optional filters and pagination.
      #
      # @return [void]
      def index
        investigations = policy_scope(Investigation).includes(:assigned_investigator, :sightings).recent
        investigations = apply_filters(investigations)
        pagy, records = pagy(investigations)
        render json: {
          data: records.map { |inv| InvestigationSerializer.new(inv).as_json },
          meta: pagination_meta(pagy)
        }
      end

      # Shows a single investigation with associations.
      #
      # @return [void]
      def show
        investigation = Investigation.includes(
          :assigned_investigator, :sightings, :investigation_notes
        ).find(params[:id])
        authorize investigation
        render json: {
          data: InvestigationDetailSerializer.new(investigation, current_user: current_user).as_json
        }
      end

      private

      # Applies query filters from params.
      #
      # @param scope [ActiveRecord::Relation]
      # @return [ActiveRecord::Relation]
      def apply_filters(scope)
        scope = scope.by_status(params[:status]) if params[:status].present?
        scope = scope.by_priority(params[:priority]) if params[:priority].present?
        scope
      end
    end
  end
end
