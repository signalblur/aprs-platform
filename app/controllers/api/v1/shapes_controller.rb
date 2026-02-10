# frozen_string_literal: true

module Api
  module V1
    # API endpoint for shape reference data.
    #
    # Provides a read-only list of all UAP shape categories.
    class ShapesController < BaseController
      # Lists all shapes ordered by name.
      #
      # @return [void]
      def index
        shapes = policy_scope(Shape).order(:name)
        render json: { data: shapes.map { |s| ShapeSerializer.new(s).as_json } }
      end
    end
  end
end
