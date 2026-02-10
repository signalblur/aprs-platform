# frozen_string_literal: true

# Authorization policy for PhysiologicalEffect records.
#
# All authenticated users can read and create effects.
# Updates are limited to admins and the parent sighting's submitter.
# Destruction is admin-only.
#
# @note ApplicationController enforces authenticate_user! before policies are checked,
#   so all users reaching these checks are guaranteed authenticated.
class PhysiologicalEffectPolicy < ApplicationPolicy
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

  # Scoping for physiological effect records.
  #
  # All authenticated users see all effects (public observational data).
  class Scope < ApplicationPolicy::Scope
    # @return [ActiveRecord::Relation] all effect records
    def resolve
      scope.all
    end
  end
end
