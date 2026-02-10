# frozen_string_literal: true

# Shared filtering logic for sighting queries.
#
# Extracted from SightingsController for reuse in both the web
# controller and the API v1 controller. Expects `params` to be
# available (standard in all ActionController subclasses).
module SightingsFilterable
  extend ActiveSupport::Concern

  private

  # Applies all active filters to the sighting query.
  #
  # @param scope [ActiveRecord::Relation] the base scope
  # @return [ActiveRecord::Relation] the filtered scope
  def apply_filters(scope)
    scope = scope.by_status(params[:status]) if params[:status].present?
    scope = scope.by_shape(params[:shape_id]) if params[:shape_id].present?
    scope = scope.search_description(params[:q]) if params[:q].present?
    scope = apply_date_filter(scope)
    apply_location_filter(scope)
  end

  # Applies date range filter when both bounds are present.
  #
  # @param scope [ActiveRecord::Relation] the current scope
  # @return [ActiveRecord::Relation] the filtered scope
  def apply_date_filter(scope)
    return scope unless params[:date_from].present? && params[:date_to].present?

    from = Date.parse(params[:date_from]).beginning_of_day
    to = Date.parse(params[:date_to]).end_of_day
    scope.observed_between(from, to)
  end

  # Applies geographic radius filter when all location params are present.
  #
  # @param scope [ActiveRecord::Relation] the current scope
  # @return [ActiveRecord::Relation] the filtered scope
  def apply_location_filter(scope)
    return scope unless params[:lat].present? && params[:lng].present? && params[:radius].present?

    scope.within_radius(params[:lat].to_f, params[:lng].to_f, params[:radius].to_f)
  end
end
