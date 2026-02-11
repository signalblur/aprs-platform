# frozen_string_literal: true

# Admin dashboard with summary statistics and charts.
#
# Provides an at-a-glance overview of system health: sightings,
# investigations, memberships, evidence, users, and API usage.
# Admin-only access enforced via DashboardPolicy.
class DashboardController < ApplicationController
  skip_after_action :verify_policy_scoped

  # Displays the admin dashboard with aggregated metrics and charts.
  #
  # @return [void]
  def index
    authorize :dashboard

    @stats = load_summary_stats
    @charts = load_chart_data
  end

  private

  # Loads aggregate counts for summary cards.
  #
  # @return [Hash]
  def load_summary_stats
    {
      total_sightings: Sighting.count,
      total_users: User.count,
      open_investigations: Investigation.open.count,
      active_memberships: Membership.active.count,
      total_evidence: Evidence.count,
      active_api_keys: ApiKey.active.count
    }
  end

  # Loads data series for dashboard charts.
  #
  # @return [Hash]
  def load_chart_data
    {
      sightings_by_status: Sighting.group(:status).count,
      users_by_role: User.group(:role).count,
      memberships_by_tier: Membership.active.group(:tier).count,
      investigations_by_status: Investigation.group(:status).count,
      evidence_by_type: Evidence.group(:evidence_type).count,
      top_shapes: Shape.joins(:sightings).group(:name).order("count_all DESC").limit(10).count,
      sightings_over_time: Sighting.group_by_month(:created_at, last: 12).count,
      user_growth: User.group_by_month(:created_at, last: 12).count
    }
  end
end
