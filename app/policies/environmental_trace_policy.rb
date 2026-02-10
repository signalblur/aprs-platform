# frozen_string_literal: true

# Authorization policy for EnvironmentalTrace records.
#
# All authenticated users can read and create traces.
# Updates are limited to admins and the parent sighting's submitter.
# Destruction is admin-only.
#
# @note ApplicationController enforces authenticate_user! before policies are checked,
#   so all users reaching these checks are guaranteed authenticated.
class EnvironmentalTracePolicy < ApplicationPolicy
  # @return [Boolean] true for all authenticated users
  def index?
    true
  end

  # @return [Boolean] true for all authenticated users
  def show?
    true
  end

  # @return [Boolean] true for all authenticated users
  def create?
    true
  end

  # @return [Boolean] true if user is an admin or the parent sighting's submitter
  def update?
    user.admin? || record.sighting.submitter == user
  end

  # @return [Boolean] true if user is an admin
  def destroy?
    user.admin?
  end

  # Scoping for environmental trace records.
  #
  # All authenticated users see all traces (public observational data).
  class Scope < ApplicationPolicy::Scope
    # @return [ActiveRecord::Relation] all trace records
    def resolve
      scope.all
    end
  end
end
