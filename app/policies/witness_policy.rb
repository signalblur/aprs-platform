# frozen_string_literal: true

# Authorization policy for Witness records.
#
# All authenticated users can read and create witness records.
# Updates are limited to admins and the parent sighting's submitter.
# Destruction is admin-only.
# Contact info visibility is restricted to investigators and admins.
#
# @note ApplicationController enforces authenticate_user! before policies are checked,
#   so all users reaching these checks are guaranteed authenticated.
class WitnessPolicy < ApplicationPolicy
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

  # Field-level PII gate for witness contact information.
  #
  # @return [Boolean] true if user is an investigator or admin
  def show_contact_info?
    user.investigator? || user.admin?
  end

  # Scoping for witness records.
  #
  # All authenticated users see all witness records.
  class Scope < ApplicationPolicy::Scope
    # @return [ActiveRecord::Relation] all witness records
    def resolve
      scope.all
    end
  end
end
