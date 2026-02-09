# frozen_string_literal: true

# Public landing page controller.
#
# Justification for skipping authentication and authorization:
# This is a public-facing landing page with no data access, no user-specific
# content, and no mutations. It serves as the root_path target for Devise
# redirects (post-login, post-logout). No authorization check is needed
# because there is no resource to authorize against.
class HomeController < ApplicationController
  skip_before_action :authenticate_user!
  skip_after_action :verify_authorized
  skip_after_action :verify_policy_scoped

  # Renders the public landing page.
  #
  # @return [void]
  def index; end
end
