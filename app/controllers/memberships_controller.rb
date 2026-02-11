# frozen_string_literal: true

# Manages membership tier assignments by admins.
#
# Admins can list, view, create, and update memberships. Non-admin users
# can only view their own membership. Memberships are never deleted —
# they are deactivated instead for audit trail.
class MembershipsController < ApplicationController
  before_action :set_membership, only: %i[show edit update]

  # Lists all memberships with optional filters and pagination.
  #
  # Admin-only. Uses both authorize (for access control) and
  # policy_scope (for consistent scoping pattern).
  #
  # @return [void]
  def index
    authorize Membership
    memberships = policy_scope(Membership).includes(:user, :granted_by).order(created_at: :desc)
    memberships = apply_filters(memberships)
    @pagy, @memberships = pagy(memberships)
  end

  # Displays a single membership.
  #
  # @return [void]
  def show
    authorize @membership
    @membership_history = Membership.where(user_id: @membership.user_id).order(created_at: :desc)
  end

  # Renders the new membership form for a specific user.
  #
  # @return [void]
  def new
    @user = User.find(params[:user_id])
    @membership = Membership.new(user: @user, starts_at: Time.current)
    authorize @membership
  end

  # Creates a new membership for a user, deactivating any existing active one.
  #
  # @return [void]
  def create
    @user = User.find(params[:user_id])
    @membership = Membership.new(membership_params)
    @membership.user = @user
    @membership.granted_by = current_user
    authorize @membership

    deactivate_existing_membership(@user)

    if @membership.save
      redirect_to @membership, notice: "Membership assigned successfully."
    else
      render :new, status: :unprocessable_content
    end
  end

  # Renders the edit membership form.
  #
  # @return [void]
  def edit
    authorize @membership
  end

  # Updates a membership (notes, active status). Tier changes require a new membership.
  #
  # @return [void]
  def update
    authorize @membership

    if @membership.update(update_params)
      redirect_to @membership, notice: "Membership updated successfully."
    else
      render :edit, status: :unprocessable_content
    end
  end

  private

  # Loads the membership by ID.
  #
  # @return [void]
  def set_membership
    @membership = Membership.find(params[:id])
  end

  # Permitted parameters for membership creation.
  #
  # @return [ActionController::Parameters]
  def membership_params
    params.require(:membership).permit(:tier, :notes, :starts_at, :expires_at)
  end

  # Permitted parameters for membership updates (no tier changes).
  #
  # @return [ActionController::Parameters]
  def update_params
    params.require(:membership).permit(:notes, :active, :expires_at)
  end

  # Deactivates any existing active membership for the user.
  #
  # @param user [User] the user whose active membership to deactivate
  # @return [void]
  def deactivate_existing_membership(user)
    user.active_membership&.update!(active: false)
  end

  # Applies query filters from params to the membership relation.
  #
  # @param scope [ActiveRecord::Relation]
  # @return [ActiveRecord::Relation]
  def apply_filters(scope)
    scope = scope.where(tier: params[:tier]) if params[:tier].present?
    scope = scope.where(active: params[:active] == "true") if params[:active].present?
    scope
  end
end
