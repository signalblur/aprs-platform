# frozen_string_literal: true

module Api
  module V1
    # Serializes Shape records to JSON-compatible hashes.
    #
    # @example
    #   Api::V1::ShapeSerializer.new(shape).as_json
    #   # => { id: 1, name: "Disc", description: "Flat disc-shaped object" }
    class ShapeSerializer
      # @param shape [Shape] the shape to serialize
      def initialize(shape)
        @shape = shape
      end

      # @return [Hash] JSON-compatible hash representation
      def as_json
        {
          id: @shape.id,
          name: @shape.name,
          description: @shape.description
        }
      end
    end
  end
end
