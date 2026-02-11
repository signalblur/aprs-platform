# frozen_string_literal: true

module Api
  module V1
    # Serializes a single Investigation with associations for show responses.
    #
    # Composes InvestigationSerializer with linked sightings, notes (gated),
    # and findings (gated). Findings and notes are only included for
    # investigators and admins.
    class InvestigationDetailSerializer
      # @param investigation [Investigation] the investigation to serialize
      # @param current_user [User, nil] used for field gating
      def initialize(investigation, current_user: nil)
        @investigation = investigation
        @current_user = current_user
      end

      # @return [Hash] JSON-compatible hash with all associations
      def as_json
        hash = InvestigationSerializer.new(@investigation).as_json
        hash[:description] = @investigation.description
        hash[:sightings] = serialize_sightings

        if show_findings?
          hash[:findings] = @investigation.findings
          hash[:notes] = serialize_notes
        end

        hash
      end

      private

      # @return [Array<Hash>]
      def serialize_sightings
        @investigation.sightings.includes(:shape).map do |sighting|
          SightingSerializer.new(sighting).as_json
        end
      end

      # @return [Array<Hash>]
      def serialize_notes
        @investigation.investigation_notes.order(created_at: :desc).map do |note|
          InvestigationNoteSerializer.new(note).as_json
        end
      end

      # @return [Boolean]
      def show_findings?
        @current_user && InvestigationPolicy.new(@current_user, @investigation).show_findings?
      end
    end
  end
end
