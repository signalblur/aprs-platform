# frozen_string_literal: true

# Authorization policy for Shape reference data.
#
# All authenticated users can read shapes (index, show).
# Only admins can modify shapes (create, update, destroy).
#
# @note ApplicationController enforces authenticate_user! before policies are checked,
#   so all users reaching these checks are guaranteed authenticated.
class ShapePolicy < ApplicationPolicy
  # Determines if the user can list all shapes.
  #
  # @return [Boolean] true for all authenticated users
  def index?
    true
  end

  # Determines if the user can view a shape.
  #
  # @return [Boolean] true for all authenticated users
  def show?
    true
  end

  # Determines if the user can create a new shape.
  #
  # @return [Boolean] true if user is an admin
  def create?
    user.admin?
  end

  # Determines if the user can update a shape.
  #
  # @return [Boolean] true if user is an admin
  def update?
    user.admin?
  end

  # Determines if the user can destroy a shape.
  #
  # @return [Boolean] true if user is an admin
  def destroy?
    user.admin?
  end

  # Scoping for shape records.
  #
  # All authenticated users see all shapes (reference data).
  class Scope < ApplicationPolicy::Scope
    # Resolves the scope to all shape records.
    #
    # @return [ActiveRecord::Relation] all shape records
    def resolve
      scope.all
    end
  end
end
