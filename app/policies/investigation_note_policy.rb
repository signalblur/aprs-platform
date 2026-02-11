# frozen_string_literal: true

# Authorization policy for InvestigationNote records.
#
# Members cannot access notes. Investigators can view and create notes
# on investigations assigned to them, and edit their own notes.
# Admins have full access.
class InvestigationNotePolicy < ApplicationPolicy
  # Determines if the user can list investigation notes.
  #
  # @return [Boolean] true for investigators (scoped to assigned) and admins
  def index?
    user.admin? || user.investigator?
  end

  # Determines if the user can view a note.
  #
  # @return [Boolean] true for admins or investigators assigned to the investigation
  def show?
    user.admin? || assigned_investigator?
  end

  # Determines if the user can create a note.
  #
  # @return [Boolean] true for admins or investigators assigned to the investigation
  def create?
    user.admin? || assigned_investigator?
  end

  # Determines if the user can update a note.
  #
  # @return [Boolean] true for admins or the note's author
  def update?
    user.admin? || record.author == user
  end

  # Determines if the user can destroy a note.
  #
  # @return [Boolean] true if user is an admin
  def destroy?
    user.admin?
  end

  private

  # Checks if the user is the assigned investigator for the note's investigation.
  #
  # @return [Boolean]
  def assigned_investigator?
    user.investigator? && record.investigation.assigned_investigator == user
  end

  # Scoping for investigation note records.
  #
  # Admins see all notes. Investigators see notes for their assigned investigations.
  class Scope < ApplicationPolicy::Scope
    # Resolves the scope based on user role.
    #
    # @return [ActiveRecord::Relation]
    def resolve
      if user.admin?
        scope.all
      elsif user.investigator?
        scope.joins(:investigation).where(investigations: { assigned_investigator_id: user.id })
      else
        scope.none
      end
    end
  end
end
