# frozen_string_literal: true

# Authorization policy for Evidence records.
#
# All authenticated users can read and create evidence.
# Updates are limited to admins and the evidence submitter.
# Destruction is admin-only.
#
# @note ApplicationController enforces authenticate_user! before policies are checked,
#   so all users reaching these checks are guaranteed authenticated.
class EvidencePolicy < ApplicationPolicy
  # @return [Boolean] true for all authenticated users
  def index?
    true
  end

  # @return [Boolean] true for all authenticated users
  def show?
    true
  end

  # Determines if the user can create evidence.
  #
  # Checks tier-based per-sighting evidence count limit. Admins bypass all limits.
  #
  # @return [Boolean] true if within tier limit
  def create?
    return true unless record.sighting

    current_count = record.sighting.evidences.count
    user.within_tier_limit?(:evidence_per_sighting, current_count)
  end

  # @return [Boolean] true if user is an admin or the evidence submitter
  def update?
    user.admin? || record.submitted_by == user
  end

  # @return [Boolean] true if user is an admin
  def destroy?
    user.admin?
  end

  # Scoping for evidence records.
  #
  # All authenticated users see all evidence (public observational data).
  class Scope < ApplicationPolicy::Scope
    # @return [ActiveRecord::Relation] all evidence records
    def resolve
      scope.all
    end
  end
end
