# frozen_string_literal: true

module Api
  module V1
    # Serializes a single Sighting with all associations for show responses.
    #
    # Composes SightingSerializer with six association arrays. Witness
    # contact_info is gated by WitnessPolicy#show_contact_info?.
    class SightingDetailSerializer
      # @param sighting [Sighting] the sighting to serialize (with associations loaded)
      # @param current_user [User, nil] used for PII gating on witness contact info
      def initialize(sighting, current_user: nil)
        @sighting = sighting
        @current_user = current_user
      end

      # @return [Hash] JSON-compatible hash with all associations
      def as_json
        SightingSerializer.new(@sighting).as_json.merge(
          physiological_effects: serialize_physiological_effects,
          psychological_effects: serialize_psychological_effects,
          equipment_effects: serialize_equipment_effects,
          environmental_traces: serialize_environmental_traces,
          evidences: serialize_evidences,
          witnesses: serialize_witnesses
        )
      end

      private

      # @return [Array<Hash>]
      def serialize_physiological_effects
        @sighting.physiological_effects.map do |effect|
          {
            id: effect.id,
            effect_type: effect.effect_type,
            description: effect.description,
            severity: effect.severity,
            onset: effect.onset,
            duration: effect.duration
          }
        end
      end

      # @return [Array<Hash>]
      def serialize_psychological_effects
        @sighting.psychological_effects.map do |effect|
          {
            id: effect.id,
            effect_type: effect.effect_type,
            description: effect.description,
            severity: effect.severity,
            onset: effect.onset,
            duration: effect.duration
          }
        end
      end

      # @return [Array<Hash>]
      def serialize_equipment_effects
        @sighting.equipment_effects.map do |effect|
          {
            id: effect.id,
            equipment_type: effect.equipment_type,
            effect_type: effect.effect_type,
            description: effect.description
          }
        end
      end

      # @return [Array<Hash>]
      def serialize_environmental_traces
        @sighting.environmental_traces.map do |trace|
          {
            id: trace.id,
            trace_type: trace.trace_type,
            description: trace.description,
            location: trace_location_hash(trace),
            measured_value: trace.measured_value,
            measurement_unit: trace.measurement_unit
          }
        end
      end

      # @return [Array<Hash>]
      def serialize_evidences
        @sighting.evidences.map do |evidence|
          {
            id: evidence.id,
            evidence_type: evidence.evidence_type,
            description: evidence.description,
            created_at: evidence.created_at.iso8601
          }
        end
      end

      # @return [Array<Hash>]
      def serialize_witnesses
        can_see_contact = @current_user && WitnessPolicy.new(@current_user, Witness.new).show_contact_info?

        @sighting.witnesses.map do |witness|
          hash = {
            id: witness.id,
            name: witness.name,
            statement: witness.statement,
            credibility_notes: witness.credibility_notes
          }
          hash[:contact_info] = witness.contact_info if can_see_contact
          hash
        end
      end

      # @param trace [EnvironmentalTrace]
      # @return [Hash, nil]
      def trace_location_hash(trace)
        return nil unless trace.location

        { lat: trace.location.latitude, lng: trace.location.longitude }
      end
    end
  end
end
