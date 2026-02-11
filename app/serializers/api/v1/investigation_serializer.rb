# frozen_string_literal: true

module Api
  module V1
    # Serializes Investigation records for list/index responses.
    #
    # Includes core fields and sighting count. Findings are intentionally
    # excluded from the summary (gated in the detail serializer).
    class InvestigationSerializer
      # @param investigation [Investigation] the investigation to serialize
      def initialize(investigation)
        @investigation = investigation
      end

      # @return [Hash] JSON-compatible hash representation
      def as_json
        {
          id: @investigation.id,
          case_number: @investigation.case_number,
          title: @investigation.title,
          status: @investigation.status,
          priority: @investigation.priority,
          classification: @investigation.classification,
          assigned_investigator_id: @investigation.assigned_investigator_id,
          sighting_count: @investigation.sightings.size,
          opened_at: @investigation.opened_at.iso8601,
          closed_at: @investigation.closed_at&.iso8601,
          created_at: @investigation.created_at.iso8601,
          updated_at: @investigation.updated_at.iso8601
        }
      end
    end
  end
end
