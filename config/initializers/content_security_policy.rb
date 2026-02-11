# Be sure to restart your server when you modify this file.

# Define an application-wide content security policy.
# See the Securing Rails Applications Guide for more information:
# https://guides.rubyonrails.org/security.html#content-security-policy-header

Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self
    policy.font_src    :self, :data
    policy.object_src  :none
    policy.base_uri    :self
    policy.form_action :self

    # Scripts: self (importmap bundles, Chartkick), plus Leaflet from jspm CDN
    policy.script_src  :self, "https://ga.jspm.io"

    # Styles: self (Tailwind), plus Leaflet CSS from unpkg CDN
    # unsafe-inline needed for Chartkick/Chart.js inline styles and Leaflet marker styles
    policy.style_src   :self, :unsafe_inline, "https://unpkg.com"

    # Images: self, data URIs (Leaflet markers), plus OpenStreetMap tiles
    policy.img_src     :self, :data, "https://tile.openstreetmap.org"

    # Connect: self for Turbo/Stimulus, plus jspm for importmap resolution
    policy.connect_src :self, "https://ga.jspm.io"
  end

  # Generate session nonces for permitted importmap and inline scripts.
  config.content_security_policy_nonce_generator = ->(request) { request.session.id.to_s }
  config.content_security_policy_nonce_directives = %w[script-src]
end
