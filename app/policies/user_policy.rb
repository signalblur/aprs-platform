# frozen_string_literal: true

# Authorization policy for User records.
#
# Admins have full CRUD access to all users.
# Members and investigators can only view and update their own record.
#
# @note Phase 1l will add tier checks via user.active_membership&.tier
class UserPolicy < ApplicationPolicy
  # Determines if the user can list all users.
  #
  # @return [Boolean] true if user is an admin
  def index?
    user.admin?
  end

  # Determines if the user can view a user record.
  #
  # @return [Boolean] true if admin or viewing own record
  def show?
    user.admin? || record == user
  end

  # Determines if the user can create a new user.
  #
  # @return [Boolean] true if user is an admin
  def create?
    user.admin?
  end

  # Determines if the user can update a user record.
  #
  # @return [Boolean] true if admin or updating own record
  def update?
    user.admin? || record == user
  end

  # Determines if the user can destroy a user record.
  #
  # @return [Boolean] true if user is an admin
  def destroy?
    user.admin?
  end

  # Scoping for user records.
  #
  # Admins see all users. Non-admins see only themselves.
  class Scope < ApplicationPolicy::Scope
    # Resolves the scope based on the user's role.
    #
    # @return [ActiveRecord::Relation] the scoped user records
    def resolve
      if user.admin?
        scope.all
      else
        scope.where(id: user.id)
      end
    end
  end
end
