# frozen_string_literal: true

# Authorization policy for the admin dashboard.
#
# Only admins can access the dashboard. The record is a symbol (:dashboard)
# since there is no underlying ActiveRecord model.
class DashboardPolicy < ApplicationPolicy
  # @return [Boolean] true if the user is an admin
  def index?
    user.admin?
  end
end
