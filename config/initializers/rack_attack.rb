# frozen_string_literal: true

# Rate limiting configuration using Rack::Attack.
#
# Throttles API requests by key prefix (authenticated) and by IP
# (unauthenticated). Also throttles login and password reset
# endpoints to prevent brute-force attacks.
class Rack::Attack
  ### Throttle API requests by API key prefix ###
  # 300 requests per minute for authenticated API consumers
  throttle("api/by_key", limit: 300, period: 60) do |req|
    if req.path.start_with?("/api/") && req.env["HTTP_X_API_KEY"].present?
      raw_key = req.env["HTTP_X_API_KEY"]
      raw_key[0, 8] if raw_key.length >= 8
    end
  end

  ### Throttle unauthenticated API requests by IP ###
  # 10 requests per minute for requests without an API key
  throttle("api/by_ip", limit: 10, period: 60) do |req|
    if req.path.start_with?("/api/") && req.env["HTTP_X_API_KEY"].blank?
      req.ip
    end
  end

  ### Throttle login attempts by IP ###
  # 5 attempts per 20 seconds
  throttle("login/by_ip", limit: 5, period: 20) do |req|
    req.ip if req.path == "/users/sign_in" && req.post?
  end

  ### Throttle password reset requests by IP ###
  # 5 attempts per hour
  throttle("password_reset/by_ip", limit: 5, period: 3600) do |req|
    req.ip if req.path == "/users/password" && req.post?
  end

  ### Custom 429 response ###
  self.throttled_responder = lambda do |_request|
    [
      429,
      { "Content-Type" => "application/json" },
      [ { error: "Rate limit exceeded. Please retry later." }.to_json ]
    ]
  end
end
