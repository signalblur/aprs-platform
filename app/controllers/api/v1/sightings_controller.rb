# frozen_string_literal: true

module Api
  module V1
    # API endpoints for UAP sighting reports.
    #
    # Provides read-only access with filtering, pagination,
    # and full detail views including all associations.
    class SightingsController < BaseController
      include SightingsFilterable

      # Lists sightings with optional filters and pagination.
      #
      # @return [void]
      def index
        sightings = policy_scope(Sighting).includes(:shape, :submitter).recent
        sightings = apply_filters(sightings)
        pagy, records = pagy(sightings)
        render json: {
          data: records.map { |s| SightingSerializer.new(s).as_json },
          meta: pagination_meta(pagy)
        }
      end

      # Shows a single sighting with all associations.
      #
      # @return [void]
      def show
        sighting = Sighting.includes(
          :shape, :submitter, :physiological_effects, :psychological_effects,
          :equipment_effects, :environmental_traces, :evidences, :witnesses
        ).find(params[:id])
        authorize sighting
        render json: { data: SightingDetailSerializer.new(sighting, current_user: current_user).as_json }
      end
    end
  end
end
