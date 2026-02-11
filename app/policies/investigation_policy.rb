# frozen_string_literal: true

# Authorization policy for Investigation records.
#
# Members can view investigations linked to their sightings.
# Investigators can view all investigations.
# Admins have full CRUD access.
# Assigned investigators can update their own investigations.
#
# @note Findings and investigation notes are gated by show_findings?
#   which restricts access to investigator and admin roles.
class InvestigationPolicy < ApplicationPolicy
  # Determines if the user can list investigations.
  #
  # @return [Boolean] true for all authenticated users
  def index?
    true
  end

  # Determines if the user can view an investigation.
  #
  # @return [Boolean] true for investigators/admins, or members with linked sightings
  def show?
    return true if user.admin? || user.investigator?

    record.sightings.exists?(submitter_id: user.id)
  end

  # Determines if the user can create a new investigation.
  #
  # @return [Boolean] true if user is an admin
  def create?
    user.admin?
  end

  # Determines if the user can update an investigation.
  #
  # @return [Boolean] true if user is an admin or the assigned investigator
  def update?
    user.admin? || record.assigned_investigator == user
  end

  # Determines if the user can destroy an investigation.
  #
  # @return [Boolean] true if user is an admin
  def destroy?
    user.admin?
  end

  # Determines if the user can link sightings to an investigation.
  #
  # @return [Boolean] true if user is an admin
  def link_sighting?
    user.admin?
  end

  # Determines if the user can unlink sightings from an investigation.
  #
  # @return [Boolean] true if user is an admin
  def unlink_sighting?
    user.admin?
  end

  # Determines if the user can view findings and investigation notes.
  #
  # @return [Boolean] true for investigators and admins
  def show_findings?
    user.admin? || user.investigator?
  end

  # Scoping for investigation records.
  #
  # Admins and investigators see all. Members see only investigations
  # linked to sightings they submitted.
  class Scope < ApplicationPolicy::Scope
    # Resolves the scope based on user role.
    #
    # @return [ActiveRecord::Relation]
    def resolve
      if user.admin? || user.investigator?
        scope.all
      else
        scope.joins(:sightings).where(sightings: { submitter_id: user.id }).distinct
      end
    end
  end
end
