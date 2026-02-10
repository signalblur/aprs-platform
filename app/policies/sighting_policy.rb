# frozen_string_literal: true

# Authorization policy for Sighting records.
#
# All authenticated users can read and create sightings.
# Updates are limited to admins and the original submitter.
# Destruction is admin-only. Anonymous sightings (submitter nil)
# can only be updated or destroyed by admins.
#
# @note ApplicationController enforces authenticate_user! before policies are checked,
#   so all users reaching these checks are guaranteed authenticated.
class SightingPolicy < ApplicationPolicy
  # Determines if the user can list all sightings.
  #
  # @return [Boolean] true for all authenticated users
  def index?
    true
  end

  # Determines if the user can view a sighting.
  #
  # @return [Boolean] true for all authenticated users
  def show?
    true
  end

  # Determines if the user can create a new sighting.
  #
  # @return [Boolean] true for all authenticated users
  def create?
    true
  end

  # Determines if the user can update a sighting.
  #
  # @return [Boolean] true if user is an admin or the record's submitter
  def update?
    user.admin? || record.submitter == user
  end

  # Determines if the user can destroy a sighting.
  #
  # @return [Boolean] true if user is an admin
  def destroy?
    user.admin?
  end

  # Scoping for sighting records.
  #
  # All authenticated users see all sightings (public observational data).
  class Scope < ApplicationPolicy::Scope
    # Resolves the scope to all sighting records.
    #
    # @return [ActiveRecord::Relation] all sighting records
    def resolve
      scope.all
    end
  end
end
