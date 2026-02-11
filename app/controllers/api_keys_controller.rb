# frozen_string_literal: true

# Manages API key lifecycle for authenticated users.
#
# Users can list, create, view, and revoke their own API keys.
# Admins can see and revoke all keys. The raw key is only displayed
# once, immediately after creation, via a flash message.
class ApiKeysController < ApplicationController
  before_action :set_api_key, only: %i[show destroy]

  # Lists the current user's API keys (admin sees all).
  #
  # @return [void]
  def index
    @api_keys = policy_scope(ApiKey).includes(:user).order(created_at: :desc)
  end

  # Renders the new API key form.
  #
  # @return [void]
  def new
    @api_key = ApiKey.new
    authorize @api_key
  end

  # Creates a new API key and passes the raw key via flash.
  #
  # @return [void]
  def create
    @api_key = ApiKey.new(api_key_params)
    @api_key.user = current_user
    authorize @api_key

    if @api_key.save
      flash[:raw_key] = @api_key.raw_key
      redirect_to @api_key, notice: "API key created successfully."
    else
      render :new, status: :unprocessable_content
    end
  end

  # Displays API key details. Shows raw key if just created (via flash).
  #
  # @return [void]
  def show
    authorize @api_key
  end

  # Revokes (destroys) an API key.
  #
  # @return [void]
  def destroy
    authorize @api_key
    @api_key.destroy!
    redirect_to api_keys_path, notice: "API key revoked."
  end

  private

  # Loads the API key by ID.
  #
  # @return [void]
  def set_api_key
    @api_key = ApiKey.find(params[:id])
  end

  # Permitted parameters for API key creation.
  #
  # @return [ActionController::Parameters]
  def api_key_params
    params.require(:api_key).permit(:name, :expires_at)
  end
end
