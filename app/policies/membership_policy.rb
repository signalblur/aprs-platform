# frozen_string_literal: true

# Authorization policy for Membership records.
#
# Only admins can list all memberships, create, and update them.
# Non-admin users can only view their own membership.
# Destroy is not permitted — use deactivation instead.
#
# @note ApplicationController enforces authenticate_user! before policies are checked,
#   so all users reaching these checks are guaranteed authenticated.
class MembershipPolicy < ApplicationPolicy
  # @return [Boolean] true if user is an admin
  def index?
    user.admin?
  end

  # @return [Boolean] true if admin or viewing own membership
  def show?
    user.admin? || record.user == user
  end

  # @return [Boolean] true if user is an admin
  def create?
    user.admin?
  end

  # @return [Boolean] true if user is an admin
  def update?
    user.admin?
  end

  # @return [Boolean] always false — use deactivation instead of deletion
  def destroy?
    false
  end

  # Scoping for membership records.
  #
  # Admins see all memberships. Non-admins see only their own.
  class Scope < ApplicationPolicy::Scope
    # @return [ActiveRecord::Relation] scoped membership records
    def resolve
      if user.admin?
        scope.all
      else
        scope.where(user: user)
      end
    end
  end
end
