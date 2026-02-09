# A11 — Server-Side Request Forgery (SSRF)

## Overview

Server-Side Request Forgery (OWASP 2021 A10) occurs when an application fetches a remote resource based on user-supplied input without validating the destination URL. Attackers exploit SSRF to make the server send crafted requests to internal services, cloud metadata endpoints, or other unintended destinations, bypassing firewalls and access controls that only restrict client-side access. SSRF can lead to internal network reconnaissance, credential theft from cloud metadata services, data exfiltration from internal APIs, and in some cases remote code execution.

The APRS platform is highly susceptible to SSRF because its core architecture involves making outbound HTTP requests to 13 external enrichment and deconfliction APIs (weather services, aircraft tracking, satellite imagery, NOTAM databases, etc.). Each of these integrations accepts sighting data (coordinates, timestamps) and returns enrichment results. If any of these API endpoint URLs are configurable, cached, or constructed from user input, an attacker can redirect requests to internal infrastructure. Additionally, Active Storage supports remote URL fetching for evidence attachments, the sighting submission form may accept external evidence URLs, and Stripe webhook callback URLs could be manipulated.

The containerized deployment using Chainguard Ruby images on cloud infrastructure makes SSRF particularly dangerous, as cloud provider metadata endpoints (169.254.169.254) can expose instance credentials, API tokens, and infrastructure configuration. DNS rebinding attacks can bypass URL validation by resolving to internal IPs after the validation check passes. The combination of multiple external API integrations and a cloud-hosted PostGIS database creates a large SSRF attack surface that requires defense in depth: URL validation, DNS resolution pinning, network-level egress controls, and response validation.

## APRS-Specific Attack Surface

- **Enrichment API integrations**: 13 external APIs (weather, aircraft, satellite, NOTAM, etc.) with configurable base URLs that could be redirected to internal endpoints
- **Active Storage remote URL fetching**: Evidence attachments uploaded via URL could target internal services
- **Webhook callback URLs**: Stripe webhook endpoint and any user-configurable notification URLs
- **Sighting enrichment pipeline**: Weather, aircraft, and satellite API calls constructed from sighting coordinates and timestamps
- **Evidence link URLs**: User-submitted URLs for YouTube videos, news articles, or external evidence
- **YouTube URL embedding**: oEmbed or iframe URLs fetched server-side for preview rendering
- **OAuth/Devise redirect handling**: `after_sign_in_path_for` and redirect URLs in authentication flows
- **DNS rebinding in API integrations**: Time-of-check-to-time-of-use (TOCTOU) gap between URL validation and actual HTTP request
- **Cloud metadata endpoint access**: Container deployments expose cloud provider metadata at well-known internal IPs

## Examples

### Basic Level

#### Example 1: SSRF via Enrichment API URL Manipulation

**Source:** https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/weather_enrichment_service.rb
class WeatherEnrichmentService
  # Attacker could manipulate the base URL via configuration tampering
  # or if the URL is constructed from user-controllable data
  def fetch_weather(sighting)
    # If base_url comes from a database record or environment variable
    # that an admin can modify, it becomes an SSRF vector
    base_url = ExternalApiConfig.find_by(name: "weather").endpoint_url
    url = "#{base_url}/v1/forecast?lat=#{sighting.latitude}&lon=#{sighting.longitude}"

    # No URL validation — could resolve to internal network
    response = Net::HTTP.get(URI(url))
    JSON.parse(response)
  end
end

# Even worse: user-supplied URL directly
# app/controllers/sightings_controller.rb
class SightingsController < ApplicationController
  def enrich
    @sighting = Sighting.find(params[:id])
    authorize @sighting

    # Attacker passes: weather_api_url=http://169.254.169.254/latest/meta-data/
    url = params[:weather_api_url]
    response = Net::HTTP.get(URI(url))
    render json: { data: response }
  end
end
```

**Secure Fix:**
```ruby
# app/services/weather_enrichment_service.rb
class WeatherEnrichmentService
  # Hardcoded allowlist of permitted API hosts.
  # NEVER construct API URLs from user input or mutable database records.
  ALLOWED_HOSTS = %w[
    api.weather.gov
    api.openweathermap.org
  ].freeze

  BASE_URL = "https://api.weather.gov".freeze

  # Fetch weather data for a sighting location.
  #
  # @param sighting [Sighting] the sighting to enrich
  # @return [Hash] parsed weather data
  # @raise [SsrfProtectionError] if URL validation fails
  def fetch_weather(sighting)
    url = "#{BASE_URL}/points/#{sighting.latitude},#{sighting.longitude}"
    validated_uri = validate_url!(url)

    response = safe_http_get(validated_uri)
    JSON.parse(response.body)
  end

  private

  # Validate a URL against the allowlist and block internal addresses.
  #
  # @param url [String] the URL to validate
  # @return [URI] the validated URI object
  # @raise [SsrfProtectionError] if the URL is not permitted
  def validate_url!(url)
    uri = URI.parse(url)

    unless uri.scheme.in?(%w[https])
      raise SsrfProtectionError, "Only HTTPS URLs are permitted"
    end

    unless ALLOWED_HOSTS.include?(uri.host)
      raise SsrfProtectionError, "Host not in allowlist: #{uri.host}"
    end

    # Resolve DNS and verify the IP is not internal
    resolved_ip = Resolv.getaddress(uri.host)
    if internal_ip?(resolved_ip)
      raise SsrfProtectionError, "Resolved to internal IP"
    end

    uri
  end

  # Check if an IP address is in a private/reserved range.
  #
  # @param ip_string [String] the IP address to check
  # @return [Boolean] true if the IP is internal
  def internal_ip?(ip_string)
    ip = IPAddr.new(ip_string)
    BLOCKED_RANGES.any? { |range| range.include?(ip) }
  end

  BLOCKED_RANGES = [
    IPAddr.new("10.0.0.0/8"),
    IPAddr.new("172.16.0.0/12"),
    IPAddr.new("192.168.0.0/16"),
    IPAddr.new("127.0.0.0/8"),
    IPAddr.new("169.254.0.0/16"),   # Link-local / cloud metadata
    IPAddr.new("0.0.0.0/8"),
    IPAddr.new("::1/128"),
    IPAddr.new("fc00::/7"),          # IPv6 unique local
    IPAddr.new("fe80::/10")          # IPv6 link-local
  ].freeze

  # Perform a safe HTTP GET with timeout and redirect limits.
  #
  # @param uri [URI] the validated URI
  # @return [Net::HTTPResponse] the HTTP response
  def safe_http_get(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.open_timeout = 5
    http.read_timeout = 10
    # Do NOT follow redirects automatically — validate each hop
    http.get(uri.request_uri)
  end
end

class SsrfProtectionError < StandardError; end
```

#### Example 2: Active Storage Remote URL Fetch to Internal Endpoints

**Source:** https://edgeguides.rubyonrails.org/active_storage_overview.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/evidences_controller.rb
class EvidencesController < ApplicationController
  def create
    @evidence = Evidence.new(evidence_params)
    @evidence.sighting = Sighting.find(params[:sighting_id])
    authorize @evidence

    # Attacker submits: remote_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    if params[:evidence][:remote_url].present?
      # Active Storage downloads the URL server-side
      downloaded = URI.open(params[:evidence][:remote_url])
      @evidence.file.attach(
        io: downloaded,
        filename: "evidence_#{SecureRandom.hex(8)}"
      )
    end

    @evidence.save!
    redirect_to @evidence.sighting
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/evidences_controller.rb
class EvidencesController < ApplicationController
  # @return [void]
  # @raise [Pundit::NotAuthorizedError] if user lacks permission
  def create
    @evidence = Evidence.new(evidence_params)
    @evidence.sighting = Sighting.find(params[:sighting_id])
    authorize @evidence

    if params[:evidence][:remote_url].present?
      attach_from_remote_url(params[:evidence][:remote_url])
    end

    if @evidence.save
      redirect_to @evidence.sighting
    else
      render :new, status: :unprocessable_entity
    end
  end

  private

  # Safely download and attach a file from a remote URL.
  # Validates the URL against SSRF protections before fetching.
  #
  # @param url [String] the remote URL to download from
  # @return [void]
  # @raise [SsrfProtectionError] if URL fails validation
  def attach_from_remote_url(url)
    validated_uri = UrlValidator.validate!(url, allowed_schemes: %w[https])

    response = SafeHttpClient.get(validated_uri, max_size: 50.megabytes)

    content_type = response.content_type
    unless content_type.in?(Evidence::ALLOWED_CONTENT_TYPES)
      raise ActiveRecord::RecordInvalid, "Content type not allowed: #{content_type}"
    end

    @evidence.file.attach(
      io: StringIO.new(response.body),
      filename: "evidence_#{SecureRandom.hex(8)}#{extension_for(content_type)}",
      content_type: content_type
    )
  end

  # @param content_type [String] the MIME type
  # @return [String] the file extension
  def extension_for(content_type)
    Rack::Mime::MIME_TYPES.invert[content_type] || ""
  end

  # @return [ActionController::Parameters]
  def evidence_params
    params.require(:evidence).permit(:description, :evidence_type, :file)
  end
end

# app/models/evidence.rb
class Evidence < ApplicationRecord
  ALLOWED_CONTENT_TYPES = %w[
    image/jpeg image/png image/webp image/heic
    video/mp4 video/quicktime
    application/pdf
  ].freeze
end
```

#### Example 3: Open Redirect in Devise Authentication Flow

**Source:** https://github.com/heartcombo/devise/wiki/How-To:-Redirect-back-to-current-page-after-sign-in,-sign-out,-sign-up,-update
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  include Pundit::Authorization

  private

  def after_sign_in_path_for(_resource)
    # Attacker crafts login link with: ?redirect_to=http://evil.com/phishing
    # or worse: ?redirect_to=http://169.254.169.254/ (SSRF if server follows)
    params[:redirect_to] || root_path
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  include Pundit::Authorization

  private

  # Safely redirect after sign-in, preventing open redirect and SSRF.
  # Only allows paths on the same host (relative paths).
  #
  # @param resource [User] the authenticated user
  # @return [String] the safe redirect path
  def after_sign_in_path_for(resource)
    stored_location = stored_location_for(resource)
    if stored_location && safe_redirect_path?(stored_location)
      stored_location
    else
      root_path
    end
  end

  # Validate that a redirect target is a safe relative path.
  # Blocks absolute URLs, protocol-relative URLs, and external hosts.
  #
  # @param path [String] the redirect path to validate
  # @return [Boolean] true if the path is safe
  def safe_redirect_path?(path)
    return false if path.blank?

    uri = URI.parse(path)

    # Must be a relative path (no scheme, no host)
    return false if uri.scheme.present?
    return false if uri.host.present?
    # Block protocol-relative URLs (//evil.com)
    return false if path.start_with?("//")
    # Must start with /
    return false unless path.start_with?("/")
    # Block path traversal
    return false if path.include?("\\")

    true
  rescue URI::InvalidURIError
    false
  end
end
```

### Intermediate Level

#### Example 4: SSRF via Webhook Callback URL Configuration

**Source:** https://portswigger.net/web-security/ssrf
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/investigation.rb
class Investigation < ApplicationRecord
  belongs_to :user
  has_many :sightings

  # Investigators can configure a webhook URL to receive updates
  # about their investigation status changes
  validates :webhook_url, format: { with: URI::DEFAULT_PARSER.make_regexp },
                          allow_blank: true
end

# app/services/investigation_notification_service.rb
class InvestigationNotificationService
  # When investigation status changes, notify via webhook
  def notify(investigation, event)
    return unless investigation.webhook_url.present?

    # No SSRF protection — investigator sets URL to internal network
    # webhook_url = "http://192.168.1.1/admin" or "http://169.254.169.254/"
    uri = URI.parse(investigation.webhook_url)
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Post.new(uri.path)
    request.body = { event: event, investigation_id: investigation.id }.to_json
    request.content_type = "application/json"
    http.request(request)
  end
end
```

**Secure Fix:**
```ruby
# app/models/investigation.rb
class Investigation < ApplicationRecord
  belongs_to :user
  has_many :sightings

  validates :webhook_url, allow_blank: true, url: { schemes: %w[https] }
  validate :webhook_url_not_internal, if: -> { webhook_url.present? }

  private

  # Validate that the webhook URL does not resolve to an internal IP.
  #
  # @return [void]
  def webhook_url_not_internal
    uri = URI.parse(webhook_url)
    resolved_ip = Resolv.getaddress(uri.host)

    if UrlValidator.internal_ip?(resolved_ip)
      errors.add(:webhook_url, "must not resolve to an internal IP address")
    end
  rescue URI::InvalidURIError, Resolv::ResolvError
    errors.add(:webhook_url, "is not a valid URL")
  end
end

# app/services/investigation_notification_service.rb
class InvestigationNotificationService
  # Send a webhook notification for an investigation event.
  # Validates the URL at send-time to prevent DNS rebinding.
  #
  # @param investigation [Investigation] the investigation
  # @param event [String] the event type
  # @return [void]
  def notify(investigation, event)
    return unless investigation.webhook_url.present?

    # Re-validate at send time to prevent DNS rebinding
    # (URL may have been valid at save time but DNS changed since)
    validated_uri = UrlValidator.validate!(
      investigation.webhook_url,
      allowed_schemes: %w[https]
    )

    response = SafeHttpClient.post(
      validated_uri,
      body: { event: event, investigation_id: investigation.id }.to_json,
      content_type: "application/json",
      timeout: 10
    )

    Rails.logger.info(
      event: "investigation.webhook.sent",
      investigation_id: investigation.id,
      webhook_host: validated_uri.host,
      response_code: response.code
    )
  rescue SsrfProtectionError => e
    Rails.logger.warn(
      event: "investigation.webhook.ssrf_blocked",
      investigation_id: investigation.id,
      error: e.message
    )
    # Disable the webhook URL to prevent repeated SSRF attempts
    investigation.update_column(:webhook_url, nil)
  end
end
```

#### Example 5: DNS Rebinding Attack on Enrichment API

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/aircraft_deconfliction_service.rb
class AircraftDeconflictionService
  def check_aircraft(sighting)
    url = build_api_url(sighting)
    uri = URI.parse(url)

    # TOCTOU vulnerability: DNS is resolved at validation time,
    # then resolved AGAIN at connection time.
    # Attacker controls DNS for their domain:
    #   First resolution: 93.184.216.34 (public IP, passes check)
    #   Second resolution: 169.254.169.254 (internal IP, SSRF!)
    resolved = Resolv.getaddress(uri.host)
    raise "Internal IP blocked" if internal_ip?(resolved)

    # Time passes... DNS TTL expires... attacker changes DNS record
    # Net::HTTP resolves the hostname AGAIN, potentially to a different IP
    response = Net::HTTP.get(uri)
    JSON.parse(response)
  end
end
```

**Secure Fix:**
```ruby
# app/services/aircraft_deconfliction_service.rb
class AircraftDeconflictionService
  ALLOWED_HOST = "opensky-network.org".freeze

  # Check for aircraft near the sighting location and time.
  #
  # @param sighting [Sighting] the sighting to deconflict
  # @return [Array<Hash>] matching aircraft records
  # @raise [SsrfProtectionError] if URL validation fails
  def check_aircraft(sighting)
    url = build_api_url(sighting)
    validated_uri = UrlValidator.validate!(url, allowed_hosts: [ALLOWED_HOST])

    # Pin the DNS resolution: resolve once and connect to that specific IP.
    # This eliminates the TOCTOU gap that enables DNS rebinding.
    response = SafeHttpClient.get_with_pinned_dns(validated_uri)
    JSON.parse(response.body)
  end

  private

  # @param sighting [Sighting] the sighting
  # @return [String] the API URL
  def build_api_url(sighting)
    time = sighting.observed_at.to_i
    "https://#{ALLOWED_HOST}/api/states/all" \
      "?lamin=#{sighting.latitude - 0.5}" \
      "&lamax=#{sighting.latitude + 0.5}" \
      "&lomin=#{sighting.longitude - 0.5}" \
      "&lomax=#{sighting.longitude + 0.5}" \
      "&time=#{time}"
  end
end

# lib/safe_http_client.rb
# HTTP client that pins DNS resolution to prevent rebinding attacks.
# Resolves the hostname once, validates the IP, then connects
# directly to that IP with the original Host header.
class SafeHttpClient
  # Perform a GET request with DNS pinning.
  #
  # @param uri [URI] the validated URI to fetch
  # @param timeout [Integer] connection timeout in seconds
  # @return [Net::HTTPResponse]
  # @raise [SsrfProtectionError] if DNS resolves to internal IP
  def self.get_with_pinned_dns(uri, timeout: 10)
    # Resolve DNS exactly once
    resolved_ip = Resolv.getaddress(uri.host)

    if UrlValidator.internal_ip?(resolved_ip)
      raise SsrfProtectionError, "DNS resolved to internal IP: #{resolved_ip}"
    end

    # Connect directly to the resolved IP, setting Host header manually
    http = Net::HTTP.new(resolved_ip, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.open_timeout = timeout
    http.read_timeout = timeout
    # Do NOT follow redirects — each redirect could rebind DNS
    http.max_retries = 0

    request = Net::HTTP::Get.new(uri.request_uri)
    request["Host"] = uri.host

    response = http.request(request)

    # If server returns a redirect, validate the new location
    if response.is_a?(Net::HTTPRedirection)
      raise SsrfProtectionError,
            "Redirect not followed for SSRF safety. Location: #{response["Location"]}"
    end

    response
  end

  # Perform a POST request with DNS pinning.
  #
  # @param uri [URI] the validated URI
  # @param body [String] the request body
  # @param content_type [String] the Content-Type header
  # @param timeout [Integer] connection timeout in seconds
  # @return [Net::HTTPResponse]
  # @raise [SsrfProtectionError] if DNS resolves to internal IP
  def self.post(uri, body:, content_type: "application/json", timeout: 10)
    resolved_ip = Resolv.getaddress(uri.host)

    if UrlValidator.internal_ip?(resolved_ip)
      raise SsrfProtectionError, "DNS resolved to internal IP: #{resolved_ip}"
    end

    http = Net::HTTP.new(resolved_ip, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.open_timeout = timeout
    http.read_timeout = timeout

    request = Net::HTTP::Post.new(uri.request_uri)
    request["Host"] = uri.host
    request["Content-Type"] = content_type
    request.body = body

    http.request(request)
  end
end
```

#### Example 6: Cloud Metadata Endpoint Access from Container

**Source:** CVE-2019-5418 (Rails file disclosure, related vector); https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
**Status:** [UNVERIFIED] (CVE is related but not identical; metadata endpoint risk is well-documented)

**Vulnerable Code:**
```ruby
# app/services/satellite_enrichment_service.rb
class SatelliteEnrichmentService
  def fetch_imagery(sighting)
    # API URL is fetched from a configuration table
    config = ExternalApiConfig.find_by!(name: "satellite_imagery")
    url = "#{config.endpoint_url}/imagery" \
          "?lat=#{sighting.latitude}&lon=#{sighting.longitude}" \
          "&date=#{sighting.observed_at.to_date}"

    # If an admin compromises the config or SQL injection changes the URL:
    # endpoint_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    # The server fetches cloud IAM credentials and returns them
    response = Net::HTTP.get(URI(url))
    JSON.parse(response)
  end
end
```

**Secure Fix:**
```ruby
# app/services/satellite_enrichment_service.rb
class SatelliteEnrichmentService
  # Hardcode the satellite imagery API host. Never load from database.
  # API keys are stored in Rails credentials, not in the database.
  API_HOST = "api.sentinel-hub.com".freeze
  API_BASE = "https://#{API_HOST}".freeze

  # Fetch satellite imagery for the sighting location and date.
  #
  # @param sighting [Sighting] the sighting to enrich
  # @return [Hash] parsed imagery metadata
  # @raise [SsrfProtectionError] if URL validation fails
  def fetch_imagery(sighting)
    url = "#{API_BASE}/api/v1/process" \
          "?lat=#{sighting.latitude}&lon=#{sighting.longitude}" \
          "&date=#{sighting.observed_at.to_date}"

    validated_uri = UrlValidator.validate!(url, allowed_hosts: [API_HOST])
    response = SafeHttpClient.get_with_pinned_dns(validated_uri)
    JSON.parse(response.body)
  end
end

# Additionally, block metadata endpoints at the network level.
# In the container orchestration / firewall rules:
#
# iptables -A OUTPUT -d 169.254.169.254 -j DROP
# iptables -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 -j DROP
#
# For Kubernetes / cloud deployments, disable the metadata endpoint
# or use IMDSv2 which requires a token header:
# AWS: HttpPutResponseHopLimit=1, RequireIMDSv2=true
#
# This is defense-in-depth: application-level URL validation
# plus network-level egress controls.

# lib/url_validator.rb
# Centralized URL validation for all outbound HTTP requests.
# Prevents SSRF by enforcing host allowlists and blocking internal IPs.
class UrlValidator
  BLOCKED_IP_RANGES = [
    IPAddr.new("0.0.0.0/8"),
    IPAddr.new("10.0.0.0/8"),
    IPAddr.new("100.64.0.0/10"),     # Carrier-grade NAT
    IPAddr.new("127.0.0.0/8"),
    IPAddr.new("169.254.0.0/16"),    # Link-local / cloud metadata
    IPAddr.new("172.16.0.0/12"),
    IPAddr.new("192.0.0.0/24"),
    IPAddr.new("192.0.2.0/24"),      # Documentation range
    IPAddr.new("192.88.99.0/24"),    # 6to4 relay
    IPAddr.new("192.168.0.0/16"),
    IPAddr.new("198.18.0.0/15"),     # Benchmarking
    IPAddr.new("198.51.100.0/24"),   # Documentation range
    IPAddr.new("203.0.113.0/24"),    # Documentation range
    IPAddr.new("224.0.0.0/4"),       # Multicast
    IPAddr.new("240.0.0.0/4"),       # Reserved
    IPAddr.new("255.255.255.255/32"),
    IPAddr.new("::1/128"),
    IPAddr.new("fc00::/7"),
    IPAddr.new("fe80::/10")
  ].freeze

  # Validate a URL for safe outbound requests.
  #
  # @param url [String] the URL to validate
  # @param allowed_schemes [Array<String>] permitted URL schemes
  # @param allowed_hosts [Array<String>] permitted hostnames (nil = any public host)
  # @return [URI] the validated URI
  # @raise [SsrfProtectionError] if validation fails
  def self.validate!(url, allowed_schemes: %w[https], allowed_hosts: nil)
    uri = URI.parse(url)

    unless uri.scheme.in?(allowed_schemes)
      raise SsrfProtectionError, "Scheme '#{uri.scheme}' not permitted"
    end

    if uri.host.blank?
      raise SsrfProtectionError, "Host is required"
    end

    # Reject IPs used directly as hostnames (bypass for DNS validation)
    if uri.host.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/) || uri.host.include?(":")
      raise SsrfProtectionError, "Direct IP addresses not permitted"
    end

    if allowed_hosts.present? && !allowed_hosts.include?(uri.host)
      raise SsrfProtectionError, "Host '#{uri.host}' not in allowlist"
    end

    # Resolve DNS and verify the IP is public
    resolved_ip = Resolv.getaddress(uri.host)
    if internal_ip?(resolved_ip)
      raise SsrfProtectionError, "Host resolves to internal IP"
    end

    uri
  rescue URI::InvalidURIError => e
    raise SsrfProtectionError, "Invalid URL: #{e.message}"
  rescue Resolv::ResolvError => e
    raise SsrfProtectionError, "DNS resolution failed: #{e.message}"
  end

  # Check if an IP address falls within a blocked range.
  #
  # @param ip_string [String] the IP address to check
  # @return [Boolean] true if the IP is in a blocked range
  def self.internal_ip?(ip_string)
    ip = IPAddr.new(ip_string)
    BLOCKED_IP_RANGES.any? { |range| range.include?(ip) }
  end
end
```

### Advanced Level

#### Example 7: SSRF via URL Validation Bypass with Special Characters

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html#case-2-application-can-send-requests-to-any-external-ip-address-or-domain-name
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/evidence_link_validator.rb
class EvidenceLinkValidator
  ALLOWED_DOMAINS = %w[youtube.com twitter.com reddit.com].freeze

  def valid_url?(url)
    uri = URI.parse(url)
    # Bypassable with:
    # "https://youtube.com@evil.com"  (userinfo component)
    # "https://evil.com#youtube.com"  (fragment component)
    # "https://youtube.com.evil.com"  (subdomain matching)
    ALLOWED_DOMAINS.any? { |domain| uri.host&.include?(domain) }
  rescue URI::InvalidURIError
    false
  end
end
```

**Secure Fix:**
```ruby
# app/services/evidence_link_validator.rb
class EvidenceLinkValidator
  ALLOWED_DOMAINS = %w[
    youtube.com
    twitter.com
    reddit.com
    x.com
  ].freeze

  # Validate that a URL points to an allowed external domain.
  # Prevents bypass via userinfo, fragments, subdomain tricks,
  # and other URL parsing ambiguities.
  #
  # @param url [String] the URL to validate
  # @return [Boolean] true if the URL is valid and allowed
  def valid_url?(url)
    return false if url.blank?

    uri = URI.parse(url)

    # Enforce HTTPS only
    return false unless uri.scheme == "https"

    # Reject URLs with userinfo (user:pass@host) which can be used for bypass
    return false if uri.userinfo.present?

    # Reject URLs with port numbers (prevent connecting to unexpected services)
    return false if uri.port != 443

    # Host must be present
    return false if uri.host.blank?

    # Reject IP addresses used as hosts
    return false if uri.host.match?(/\A[\d.:]+\z/)

    # Exact domain or subdomain match (not substring)
    # "youtube.com" matches "www.youtube.com" but not "youtube.com.evil.com"
    host = uri.host.downcase
    ALLOWED_DOMAINS.any? do |domain|
      host == domain || host.end_with?(".#{domain}")
    end
  rescue URI::InvalidURIError
    false
  end
end

# app/models/evidence.rb
class Evidence < ApplicationRecord
  belongs_to :sighting

  validates :external_url, allow_blank: true, format: { with: /\Ahttps:\/\// }
  validate :external_url_allowed_domain, if: -> { external_url.present? }

  private

  # @return [void]
  def external_url_allowed_domain
    validator = EvidenceLinkValidator.new
    return if validator.valid_url?(external_url)

    errors.add(:external_url, "must link to an approved domain (YouTube, Twitter, Reddit)")
  end
end
```

#### Example 8: SSRF in Deconfliction Pipeline via Redirect Following

**Source:** https://cwe.mitre.org/data/definitions/918.html (CWE-918: Server-Side Request Forgery)
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/services/deconfliction_pipeline_service.rb
class DeconflictionPipelineService
  APIS = {
    weather: "https://api.weather.gov",
    aircraft: "https://opensky-network.org",
    satellite: "https://api.sentinel-hub.com",
    notam: "https://api.faa.gov"
  }.freeze

  def run_pipeline(sighting)
    APIS.map do |source, base_url|
      url = build_url(source, base_url, sighting)
      uri = URI.parse(url)

      # Follows redirects automatically — a compromised or malicious
      # API server can redirect to internal endpoints
      response = Net::HTTP.get_response(uri)
      while response.is_a?(Net::HTTPRedirection)
        # Each redirect could go anywhere, including internal IPs
        response = Net::HTTP.get_response(URI(response["Location"]))
      end

      DeconflictionResult.create!(
        sighting: sighting,
        source: source.to_s,
        raw_response: response.body
      )
    end
  end
end
```

**Secure Fix:**
```ruby
# app/services/deconfliction_pipeline_service.rb
class DeconflictionPipelineService
  # Each API source is mapped to its allowed host for strict validation.
  APIS = {
    weather: { host: "api.weather.gov", base: "https://api.weather.gov" },
    aircraft: { host: "opensky-network.org", base: "https://opensky-network.org" },
    satellite: { host: "api.sentinel-hub.com", base: "https://api.sentinel-hub.com" },
    notam: { host: "api.faa.gov", base: "https://api.faa.gov" }
  }.freeze

  MAX_REDIRECTS = 3

  # Run the full deconfliction pipeline for a sighting.
  # Each API call is independently validated against its allowlist.
  #
  # @param sighting [Sighting] the sighting to deconflict
  # @return [Array<DeconflictionResult>] the results from each source
  def run_pipeline(sighting)
    APIS.map do |source, config|
      fetch_with_safe_redirects(source, config, sighting)
    rescue SsrfProtectionError => e
      Rails.logger.warn(
        event: "deconfliction.ssrf_blocked",
        source: source,
        sighting_id: sighting.id,
        error: e.message
      )
      DeconflictionResult.create!(
        sighting: sighting,
        source: source.to_s,
        status: "error",
        error_message: "SSRF protection triggered"
      )
    rescue StandardError => e
      Rails.logger.error(
        event: "deconfliction.api_error",
        source: source,
        sighting_id: sighting.id,
        error_class: e.class.name,
        error_message: e.message
      )
      DeconflictionResult.create!(
        sighting: sighting,
        source: source.to_s,
        status: "error",
        error_message: "API request failed"
      )
    end
  end

  private

  # Fetch from an API with safe redirect handling.
  # Each redirect hop is validated against the source's allowed host
  # and blocked IP ranges. Maximum redirect depth is enforced.
  #
  # @param source [Symbol] the API source identifier
  # @param config [Hash] the API configuration
  # @param sighting [Sighting] the sighting
  # @return [DeconflictionResult]
  def fetch_with_safe_redirects(source, config, sighting)
    url = build_url(source, config[:base], sighting)
    redirect_count = 0

    loop do
      validated_uri = UrlValidator.validate!(
        url,
        allowed_hosts: [config[:host]]
      )

      response = SafeHttpClient.get_with_pinned_dns(validated_uri)

      if response.is_a?(Net::HTTPRedirection)
        redirect_count += 1
        if redirect_count > MAX_REDIRECTS
          raise SsrfProtectionError, "Too many redirects (max #{MAX_REDIRECTS})"
        end

        new_location = response["Location"]
        # Validate the redirect target against the SAME allowlist
        url = new_location
        next
      end

      return DeconflictionResult.create!(
        sighting: sighting,
        source: source.to_s,
        status: "success",
        raw_response: response.body.truncate(10_000)
      )
    end
  end
end
```

#### Example 9: YouTube oEmbed SSRF via Unvalidated Video URL

**Source:** https://oembed.com/ ; https://hackerone.com/reports/1439593 (SSRF via oEmbed)
**Status:** [UNVERIFIED] (HackerOne report reference is representative of the class of vulnerability)

**Vulnerable Code:**
```ruby
# app/services/youtube_embed_service.rb
class YoutubeEmbedService
  OEMBED_URL = "https://www.youtube.com/oembed".freeze

  def fetch_embed(video_url)
    # User submits video_url in the evidence form
    # Attacker submits: video_url=http://169.254.169.254/latest/meta-data/
    # The server fetches the oEmbed endpoint with the attacker-controlled URL
    url = "#{OEMBED_URL}?url=#{CGI.escape(video_url)}&format=json"
    response = Net::HTTP.get(URI(url))
    JSON.parse(response)
  rescue StandardError
    nil
  end
end
```

**Secure Fix:**
```ruby
# app/services/youtube_embed_service.rb
class YoutubeEmbedService
  OEMBED_URL = "https://www.youtube.com/oembed".freeze
  OEMBED_HOST = "www.youtube.com".freeze

  # Valid YouTube URL patterns.
  # Only these formats are accepted as video URLs.
  YOUTUBE_URL_PATTERN = %r{
    \Ahttps://(www\.)?youtube\.com/watch\?v=[a-zA-Z0-9_-]{11}\z |
    \Ahttps://youtu\.be/[a-zA-Z0-9_-]{11}\z
  }x

  # Fetch oEmbed data for a YouTube video URL.
  #
  # @param video_url [String] the YouTube video URL
  # @return [Hash, nil] parsed oEmbed data or nil if invalid
  # @raise [SsrfProtectionError] if URL validation fails
  def fetch_embed(video_url)
    # Step 1: Validate that the input is actually a YouTube URL
    unless video_url.match?(YOUTUBE_URL_PATTERN)
      Rails.logger.warn(
        event: "youtube_embed.invalid_url",
        url_host: safe_extract_host(video_url)
      )
      return nil
    end

    # Step 2: Build the oEmbed request URL
    oembed_request_url = "#{OEMBED_URL}?url=#{CGI.escape(video_url)}&format=json"

    # Step 3: Validate and fetch using SSRF-safe client
    validated_uri = UrlValidator.validate!(
      oembed_request_url,
      allowed_hosts: [OEMBED_HOST]
    )

    response = SafeHttpClient.get_with_pinned_dns(validated_uri, timeout: 5)

    return nil unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  rescue JSON::ParserError, SsrfProtectionError => e
    Rails.logger.warn(
      event: "youtube_embed.fetch_failed",
      error_class: e.class.name
    )
    nil
  end

  private

  # Safely extract the host from a URL for logging (no PII risk).
  #
  # @param url [String] the URL
  # @return [String] the host or "unparseable"
  def safe_extract_host(url)
    URI.parse(url.to_s).host || "no_host"
  rescue URI::InvalidURIError
    "unparseable"
  end
end
```

#### Example 10: SSRF via IPv6 Address Encoding to Bypass IP Blocklists

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# lib/url_validator_naive.rb
class UrlValidatorNaive
  BLOCKED_RANGES = [
    IPAddr.new("10.0.0.0/8"),
    IPAddr.new("172.16.0.0/12"),
    IPAddr.new("192.168.0.0/16"),
    IPAddr.new("127.0.0.0/8"),
    IPAddr.new("169.254.0.0/16")
  ].freeze

  def safe?(url)
    uri = URI.parse(url)
    # Only checks IPv4 ranges — IPv6-mapped addresses bypass this:
    # http://[::ffff:169.254.169.254]/ resolves to the metadata endpoint
    # http://[0:0:0:0:0:ffff:a9fe:a9fe]/ is the same in full notation
    # http://[::1]/ is IPv6 localhost
    #
    # Also missing:
    # - Decimal IP: http://2852039166/ (169.254.169.254 as decimal)
    # - Octal IP: http://0251.0376.0251.0376/ (169.254.169.254 as octal)
    # - URL-encoded: http://%31%36%39.%32%35%34.%31%36%39.%32%35%34/
    resolved = Resolv.getaddress(uri.host)
    ip = IPAddr.new(resolved)
    !BLOCKED_RANGES.any? { |range| range.include?(ip) }
  end
end
```

**Secure Fix:**
```ruby
# lib/url_validator.rb (comprehensive version)
class UrlValidator
  # Comprehensive blocklist covering IPv4, IPv6, and mapped addresses.
  BLOCKED_IP_RANGES = [
    # IPv4 private and reserved
    IPAddr.new("0.0.0.0/8"),
    IPAddr.new("10.0.0.0/8"),
    IPAddr.new("100.64.0.0/10"),
    IPAddr.new("127.0.0.0/8"),
    IPAddr.new("169.254.0.0/16"),
    IPAddr.new("172.16.0.0/12"),
    IPAddr.new("192.0.0.0/24"),
    IPAddr.new("192.0.2.0/24"),
    IPAddr.new("192.88.99.0/24"),
    IPAddr.new("192.168.0.0/16"),
    IPAddr.new("198.18.0.0/15"),
    IPAddr.new("198.51.100.0/24"),
    IPAddr.new("203.0.113.0/24"),
    IPAddr.new("224.0.0.0/4"),
    IPAddr.new("240.0.0.0/4"),
    IPAddr.new("255.255.255.255/32"),
    # IPv6 private and reserved
    IPAddr.new("::1/128"),           # Loopback
    IPAddr.new("::/128"),            # Unspecified
    IPAddr.new("::ffff:0:0/96"),     # IPv4-mapped IPv6 (covers ::ffff:169.254.x.x)
    IPAddr.new("64:ff9b::/96"),      # NAT64
    IPAddr.new("100::/64"),          # Discard prefix
    IPAddr.new("2001:db8::/32"),     # Documentation
    IPAddr.new("fc00::/7"),          # Unique local
    IPAddr.new("fe80::/10")          # Link-local
  ].freeze

  # Validate a URL, blocking all forms of internal address encoding.
  #
  # @param url [String] the URL to validate
  # @param allowed_schemes [Array<String>] permitted schemes
  # @param allowed_hosts [Array<String>, nil] permitted hostnames
  # @return [URI] the validated URI
  # @raise [SsrfProtectionError] if validation fails
  def self.validate!(url, allowed_schemes: %w[https], allowed_hosts: nil)
    # Reject URLs with non-ASCII characters or encoding tricks
    raise SsrfProtectionError, "URL contains non-ASCII" unless url.ascii_only?

    uri = URI.parse(url)

    unless uri.scheme&.downcase.in?(allowed_schemes)
      raise SsrfProtectionError, "Scheme not permitted"
    end

    raise SsrfProtectionError, "Host required" if uri.host.blank?
    raise SsrfProtectionError, "Userinfo not permitted" if uri.userinfo.present?

    host = uri.host.downcase

    # Block direct IP addresses (IPv4, IPv6, decimal, octal, hex)
    if host.match?(/\A[\d.]+\z/) ||        # IPv4
       host.start_with?("[") ||              # IPv6 bracket notation
       host.match?(/\A0[xX][\da-fA-F]+/) || # Hex IP
       host.match?(/\A0\d+/)                 # Octal IP
      raise SsrfProtectionError, "Direct IP addresses not permitted"
    end

    if allowed_hosts.present?
      unless allowed_hosts.any? { |ah| host == ah || host.end_with?(".#{ah}") }
        raise SsrfProtectionError, "Host not in allowlist"
      end
    end

    # Resolve all addresses (IPv4 and IPv6) and verify ALL are public
    addresses = Resolv.getaddresses(uri.host)
    raise SsrfProtectionError, "DNS resolution returned no addresses" if addresses.empty?

    addresses.each do |addr|
      if internal_ip?(addr)
        raise SsrfProtectionError, "Resolved to blocked IP: #{addr}"
      end
    end

    uri
  rescue URI::InvalidURIError => e
    raise SsrfProtectionError, "Invalid URL: #{e.message}"
  rescue Resolv::ResolvError => e
    raise SsrfProtectionError, "DNS resolution failed: #{e.message}"
  end

  # Check if an IP address is in any blocked range.
  # Handles both IPv4 and IPv6 addresses, including mapped forms.
  #
  # @param ip_string [String] the IP address
  # @return [Boolean]
  def self.internal_ip?(ip_string)
    ip = IPAddr.new(ip_string)

    # If it is an IPv4-mapped IPv6 address, also check the IPv4 form
    if ip.ipv6? && ip_string.start_with?("::ffff:")
      ipv4_part = ip_string.sub("::ffff:", "")
      return true if internal_ip?(ipv4_part)
    end

    BLOCKED_IP_RANGES.any? { |range| range.include?(ip) }
  rescue IPAddr::InvalidAddressError
    true # If we cannot parse the IP, block it
  end
end
```

## Checklist

- [ ] All outbound HTTP requests use `UrlValidator.validate!` before connection
- [ ] Host allowlists are hardcoded constants, never loaded from database or user input
- [ ] DNS resolution is pinned (resolve once, connect to that IP) to prevent DNS rebinding
- [ ] All enrichment/deconfliction API base URLs are hardcoded, not configurable at runtime
- [ ] `BLOCKED_IP_RANGES` covers: IPv4 private, IPv6 private, IPv4-mapped IPv6, link-local, cloud metadata (169.254.0.0/16)
- [ ] HTTP redirects are NOT followed automatically; each redirect target is validated
- [ ] Maximum redirect depth is enforced (3 or fewer hops)
- [ ] Direct IP addresses (decimal, octal, hex, IPv6 bracket notation) are rejected in URL hosts
- [ ] URL userinfo component (`user:pass@host`) is rejected
- [ ] Only HTTPS scheme is permitted for outbound requests
- [ ] Active Storage remote URL fetching validates URLs through SSRF protections
- [ ] Evidence external URLs are validated against a domain allowlist with proper subdomain matching
- [ ] Devise redirect paths (`after_sign_in_path_for`) only accept relative paths on the same host
- [ ] YouTube/oEmbed URLs are validated against strict patterns before server-side fetching
- [ ] Cloud metadata endpoint (169.254.169.254) is blocked at both application and network levels
- [ ] Container egress firewall rules block traffic to 169.254.0.0/16 and other internal ranges
- [ ] `Resolv.getaddresses` (plural) is used to check ALL resolved IPs, not just the first one
