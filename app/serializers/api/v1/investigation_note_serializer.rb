# frozen_string_literal: true

module Api
  module V1
    # Serializes InvestigationNote records for API responses.
    class InvestigationNoteSerializer
      # @param note [InvestigationNote] the note to serialize
      def initialize(note)
        @note = note
      end

      # @return [Hash] JSON-compatible hash representation
      def as_json
        {
          id: @note.id,
          note_type: @note.note_type,
          content: @note.content,
          author_id: @note.author_id,
          created_at: @note.created_at.iso8601
        }
      end
    end
  end
end
