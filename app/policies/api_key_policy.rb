# frozen_string_literal: true

# Authorization policy for API key management.
#
# All authenticated users can list and create their own API keys.
# Viewing and destroying keys is restricted to the key owner or admins.
#
# @note ApplicationController enforces authenticate_user! before policies are checked,
#   so all users reaching these checks are guaranteed authenticated.
class ApiKeyPolicy < ApplicationPolicy
  # @return [Boolean] true for all authenticated users
  def index?
    true
  end

  # Determines if the user can create a new API key.
  #
  # Checks tier-based API key count limit. Admins bypass all limits.
  #
  # @return [Boolean] true if within tier limit
  def create?
    current_count = user.api_keys.where(active: true).count
    user.within_tier_limit?(:api_keys, current_count)
  end

  # @return [Boolean] true if user is the key owner or an admin
  def show?
    owner_or_admin?
  end

  # @return [Boolean] true if user is the key owner or an admin
  def destroy?
    owner_or_admin?
  end

  # Scoping for API key records.
  #
  # Admins see all keys; other users see only their own.
  class Scope < ApplicationPolicy::Scope
    # @return [ActiveRecord::Relation]
    def resolve
      if user.admin?
        scope.all
      else
        scope.where(user: user)
      end
    end
  end

  private

  # @return [Boolean] true if the user owns the record or is an admin
  def owner_or_admin?
    record.user == user || user.admin?
  end
end
