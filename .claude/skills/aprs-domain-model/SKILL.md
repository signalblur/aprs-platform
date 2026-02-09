# Skill: aprs-domain-model

## Trigger

Invoked internally by other agents during the build-feature pipeline. Not typically called directly by the user.

Can also be invoked manually with `/aprs-domain-model` to display the full domain model reference.

## Description

Canonical domain model reference for the APRS platform. Documents all models, their columns, associations, validations, and business rules. Agents must consult this skill when building features that interact with the data layer.

---

## Models

### User

The central identity model. Authenticated via Devise, authorized via Pundit role checks.

**Table:** `users`

| Column               | Type        | Constraints               | Notes                                    |
|----------------------|-------------|---------------------------|------------------------------------------|
| `id`                 | `bigint`    | PK, auto-increment        |                                          |
| `email`              | `string`    | NOT NULL, unique, indexed  | Devise field                             |
| `encrypted_password` | `string`    | NOT NULL                  | Devise field, bcrypt (stretches >= 12)   |
| `role`               | `integer`   | NOT NULL, default: 0      | Enum: `member` (0), `investigator` (1), `admin` (2) |
| `stripe_customer_id` | `string`    | nullable, unique, indexed  | Set when user subscribes via Stripe      |
| `first_name`         | `string`    | NOT NULL                  |                                          |
| `last_name`          | `string`    | NOT NULL                  |                                          |
| `failed_attempts`    | `integer`   | NOT NULL, default: 0      | Devise lockable                          |
| `locked_at`          | `datetime`  | nullable                  | Devise lockable                          |
| `unlock_token`       | `string`    | nullable, unique           | Devise lockable                          |
| `reset_password_token` | `string`  | nullable, unique           | Devise recoverable                       |
| `reset_password_sent_at` | `datetime` | nullable              | Devise recoverable                       |
| `confirmation_token` | `string`    | nullable, unique           | Devise confirmable                       |
| `confirmed_at`       | `datetime`  | nullable                  | Devise confirmable                       |
| `confirmation_sent_at` | `datetime` | nullable                 | Devise confirmable                       |
| `unconfirmed_email`  | `string`    | nullable                  | Devise reconfirmable                     |
| `created_at`         | `datetime`  | NOT NULL                  |                                          |
| `updated_at`         | `datetime`  | NOT NULL                  |                                          |

**Associations:**
- `has_many :sightings, foreign_key: :submitter_id, dependent: :restrict_with_error`
- `has_many :investigations, foreign_key: :investigator_id, dependent: :restrict_with_error`
- `has_one :membership, dependent: :destroy`
- `has_many :api_keys, dependent: :destroy`
- `has_many :audit_logs, as: :actor`

**Validations:**
- `validates :email, presence: true, uniqueness: true, format: { with: URI::MailTo::EMAIL_REGEXP }`
- `validates :role, presence: true, inclusion: { in: roles.keys }`
- `validates :first_name, :last_name, presence: true`

**Enums:**
```ruby
enum :role, { member: 0, investigator: 1, admin: 2 }, validate: true
```

**Instance Methods:**
```ruby
# Returns the user's active membership, or nil if no active membership exists.
#
# @return [Membership, nil] the active membership record
def active_membership
  membership if membership&.active?
end
```

**Business Rules:**
- Default role is `member` on registration.
- Role changes are admin-only operations.
- Payment tier is determined solely by the associated `Membership` record, never stored on User.
- Pundit policies check tier via `user.active_membership&.tier`.
- `stripe_customer_id` is set when the user first subscribes; never overwritten.
- Deletion is restricted if the user has associated sightings or investigations (use `restrict_with_error`).

---

### Sighting

The core data model. Represents a single UAP observation report with geospatial and temporal data.

**Table:** `sightings`

| Column               | Type          | Constraints                | Notes                                       |
|----------------------|---------------|----------------------------|---------------------------------------------|
| `id`                 | `bigint`      | PK, auto-increment         |                                             |
| `submitter_id`       | `bigint`      | nullable, FK -> users, indexed | The user who submitted the report (nullable for anonymous)   |
| `shape_id`           | `bigint`      | NOT NULL, FK -> shapes, indexed | Reference to shape classification        |
| `description`        | `text`        | NOT NULL                   | Free-text description of the sighting       |
| `duration_seconds`   | `integer`     | nullable                   | How long the phenomenon was observed        |
| `location`           | `st_point`    | geographic, SRID 4326, indexed (GiST) | PostGIS geography point          |
| `altitude_feet`      | `decimal`     | nullable                   | Estimated altitude of the phenomenon        |
| `observed_at`        | `timestamptz` | NOT NULL, indexed          | When the sighting occurred (stored as UTC)  |
| `observed_timezone`  | `string`      | NOT NULL                   | IANA timezone (e.g., "America/New_York")    |
| `num_witnesses`      | `integer`     | NOT NULL, default: 1       | Number of witnesses present                 |
| `visibility_conditions` | `string`   | nullable                   | Weather/visibility at time of sighting      |
| `weather_notes`      | `text`        | nullable                   | Additional weather observations             |
| `media_source`       | `string`      | nullable                   | Where media came from (phone, dashcam, etc.)|
| `status`             | `integer`     | NOT NULL, default: 0       | Enum: `submitted` (0), `under_review` (1), `verified` (2), `rejected` (3) |
| `created_at`         | `datetime`    | NOT NULL                   |                                             |
| `updated_at`         | `datetime`    | NOT NULL                   |                                             |

**Associations:**
- `belongs_to :submitter, class_name: "User", optional: true`
- `belongs_to :shape`
- `has_one :investigation, dependent: :nullify`
- `has_many :evidences, dependent: :destroy`
- `has_many :witnesses, dependent: :destroy`
- `has_one :weather_condition, dependent: :destroy`
- `has_one :deconfliction_result, dependent: :destroy`
- `has_many :physiological_effects, dependent: :destroy`
- `has_many :psychological_effects, dependent: :destroy`
- `has_many :equipment_effects, dependent: :destroy`
- `has_many :environmental_traces, dependent: :destroy`
- `has_many :audit_logs, as: :auditable`

**Validations:**
- `validates :description, presence: true, length: { minimum: 20, maximum: 10_000 }`
- `validates :observed_at, presence: true`
- `validates :observed_timezone, presence: true, inclusion: { in: ActiveSupport::TimeZone::MAPPING.values }`
- `validates :num_witnesses, numericality: { greater_than_or_equal_to: 1 }`
- `validates :duration_seconds, numericality: { greater_than: 0 }, allow_nil: true`
- `validates :status, presence: true`

**Enums:**
```ruby
enum :status, { submitted: 0, under_review: 1, verified: 2, rejected: 3 }, validate: true
```

**Scopes:**
```ruby
scope :within_radius, ->(lat, lng, meters) { where("ST_DWithin(location, ST_Point(?, ?, 4326)::geography, ?)", lng, lat, meters) }
scope :recent, -> { order(observed_at: :desc) }
scope :by_shape, ->(shape_id) { where(shape_id: shape_id) }
scope :by_status, ->(status) { where(status: status) }
scope :observed_between, ->(start_date, end_date) { where(observed_at: start_date..end_date) }
```

**Business Rules:**
- Location is stored as a PostGIS geography point (longitude, latitude) with SRID 4326.
- `observed_at` is always stored in UTC; `observed_timezone` preserves the observer's local timezone.
- Status transitions: `submitted -> under_review -> verified|rejected`. No skipping steps. No going backward.
- A sighting can have at most one investigation.
- Description minimum 20 characters to discourage low-effort submissions.

---

### Shape

Reference/seed data for UAP shape classifications. Seeded at application setup; rarely changes.

**Table:** `shapes`

| Column        | Type      | Constraints               | Notes                         |
|---------------|-----------|---------------------------|-------------------------------|
| `id`          | `bigint`  | PK, auto-increment        |                               |
| `name`        | `string`  | NOT NULL, unique, indexed  | e.g., "Sphere", "Triangle"   |
| `description` | `text`    | nullable                  | Description of the shape      |
| `created_at`  | `datetime`| NOT NULL                  |                               |
| `updated_at`  | `datetime`| NOT NULL                  |                               |

**Associations:**
- `has_many :sightings, dependent: :restrict_with_error`

**Validations:**
- `validates :name, presence: true, uniqueness: true`

**Seed Categories (25+):**
Sphere, Orb, Triangle, Boomerang/V-Shape, Chevron, Diamond, Disk/Saucer, Oval/Egg, Cylinder/Cigar, Rectangle, Cross, Star, Cone, Teardrop, Fireball, Light (single), Light (multiple/formation), Flash/Strobe, Beam/Ray, Cloud-like/Amorphous, Tic-Tac/Capsule, Dumbbell, Saturn-shape, Morphing/Shape-shifting, Other/Unknown.

**Business Rules:**
- Shapes are seed data loaded via `db/seeds.rb`.
- Shapes should not be deleted if sightings reference them (`restrict_with_error`).
- New shapes can be added by admins but this is rare.

---

### Investigation

Case management for verified sightings. Assigned to investigators.

**Table:** `investigations`

| Column           | Type        | Constraints                    | Notes                                   |
|------------------|-------------|--------------------------------|-----------------------------------------|
| `id`             | `bigint`    | PK, auto-increment             |                                         |
| `sighting_id`    | `bigint`    | NOT NULL, FK -> sightings, unique, indexed | One investigation per sighting |
| `investigator_id`| `bigint`    | NOT NULL, FK -> users, indexed  | Must have role `investigator` or `admin`|
| `title`          | `string`    | NOT NULL                       | Case title                              |
| `summary`        | `text`      | nullable                       | Investigation summary/notes             |
| `status`         | `integer`   | NOT NULL, default: 0           | Enum: `open` (0), `in_progress` (1), `closed` (2) |
| `priority`       | `integer`   | NOT NULL, default: 0           | Enum: `low` (0), `medium` (1), `high` (2), `critical` (3) |
| `opened_at`      | `datetime`  | NOT NULL                       | When the investigation was opened       |
| `closed_at`      | `datetime`  | nullable                       | When the investigation was closed       |
| `created_at`     | `datetime`  | NOT NULL                       |                                         |
| `updated_at`     | `datetime`  | NOT NULL                       |                                         |

**Associations:**
- `belongs_to :sighting`
- `belongs_to :investigator, class_name: "User"`
- `has_many :evidences, dependent: :destroy`
- `has_many :audit_logs, as: :auditable`

**Validations:**
- `validates :title, presence: true`
- `validates :status, presence: true`
- `validates :priority, presence: true`
- `validates :opened_at, presence: true`
- `validate :investigator_has_required_role`

**Enums:**
```ruby
enum :status, { open: 0, in_progress: 1, closed: 2 }, validate: true
enum :priority, { low: 0, medium: 1, high: 2, critical: 3 }, validate: true
```

**Business Rules:**
- Only users with role `investigator` or `admin` can be assigned as investigator.
- One investigation per sighting (unique constraint on `sighting_id`).
- `closed_at` must be set when status transitions to `closed`.
- Sighting must have status `under_review` or `verified` before an investigation can be opened.

---

### Evidence

Files and documents attached to sightings or investigations via Active Storage.

**Table:** `evidences`

| Column              | Type      | Constraints                          | Notes                               |
|---------------------|-----------|--------------------------------------|--------------------------------------|
| `id`                | `bigint`  | PK, auto-increment                   |                                      |
| `sighting_id`       | `bigint`  | nullable, FK -> sightings, indexed   | Evidence for a sighting              |
| `investigation_id`  | `bigint`  | nullable, FK -> investigations, indexed | Evidence for an investigation     |
| `description`       | `text`    | nullable                             | Description of the evidence          |
| `evidence_type`     | `integer` | NOT NULL, default: 0                 | Enum: `photo` (0), `video` (1), `audio` (2), `document` (3), `other` (4) |
| `submitted_by_id`   | `bigint`  | NOT NULL, FK -> users, indexed       | Who uploaded the evidence            |
| `created_at`        | `datetime`| NOT NULL                             |                                      |
| `updated_at`        | `datetime`| NOT NULL                             |                                      |

**Associations:**
- `belongs_to :sighting, optional: true`
- `belongs_to :investigation, optional: true`
- `belongs_to :submitted_by, class_name: "User"`
- `has_one_attached :file` (Active Storage)

**Validations:**
- `validates :evidence_type, presence: true`
- `validate :belongs_to_sighting_or_investigation` (must have exactly one parent)
- `validate :file_content_type_allowed`
- `validate :file_size_within_limit`

**Enums:**
```ruby
enum :evidence_type, { photo: 0, video: 1, audio: 2, document: 3, other: 4 }, validate: true
```

**Business Rules:**
- Evidence must belong to either a sighting or an investigation, but not both and not neither.
- File uploads must validate both content-type AND magic bytes (not just extension).
- Allowed content types: `image/jpeg`, `image/png`, `image/webp`, `video/mp4`, `audio/mpeg`, `audio/wav`, `application/pdf`.
- Maximum file size: 100 MB.
- Files stored via Active Storage on DigitalOcean Spaces (S3-compatible).
- Serving files requires authorization (no public URLs without policy check).

---

### Membership

Payment tier tracking. Linked to Stripe subscriptions.

**Table:** `memberships`

| Column               | Type        | Constraints                    | Notes                                    |
|----------------------|-------------|--------------------------------|------------------------------------------|
| `id`                 | `bigint`    | PK, auto-increment             |                                          |
| `user_id`            | `bigint`    | NOT NULL, FK -> users, unique, indexed | One membership per user           |
| `tier`               | `integer`   | NOT NULL, default: 0           | Enum: `basic` (0), `premium` (1), `platinum` (2) |
| `status`             | `integer`   | NOT NULL, default: 0           | Enum: `active` (0), `past_due` (1), `canceled` (2), `unpaid` (3) |
| `stripe_subscription_id` | `string` | nullable, unique, indexed    | Stripe subscription ID                   |
| `current_period_end` | `datetime`  | nullable                      | When the current billing period ends     |
| `cancel_at_period_end` | `boolean` | NOT NULL, default: false       | Whether subscription cancels at period end |
| `past_due_since`     | `datetime`  | nullable                      | When payment became past due (enables 7-day grace period) |
| `trial_end`          | `datetime`  | nullable                      | Trial period end date                    |
| `created_at`         | `datetime`  | NOT NULL                       |                                          |
| `updated_at`         | `datetime`  | NOT NULL                       |                                          |

**Associations:**
- `belongs_to :user`
- `has_many :audit_logs, as: :auditable`

**Validations:**
- `validates :tier, presence: true`
- `validates :status, presence: true`
- `validates :user_id, uniqueness: true`

**Enums:**
```ruby
enum :tier, { basic: 0, premium: 1, platinum: 2 }, validate: true
enum :status, { active: 0, past_due: 1, canceled: 2, unpaid: 3 }, validate: true
```

**Business Rules:**
- One membership per user (unique constraint on `user_id`).
- Tier determines feature access; checked via Pundit policies (`user.active_membership&.tier`).
- Membership is the single source of truth for payment tier; User model never stores tier.
- Updates from Stripe webhooks use pessimistic locking (`membership.lock!`).
- Free tier is implicit — users without an active Membership record are "free". No Stripe subscription required.
- `current_period_end` is updated from Stripe subscription data.

---

### ApiKey

API authentication tokens for external integrations.

**Table:** `api_keys`

| Column           | Type        | Constraints                    | Notes                                      |
|------------------|-------------|--------------------------------|--------------------------------------------|
| `id`             | `bigint`    | PK, auto-increment             |                                            |
| `user_id`        | `bigint`    | NOT NULL, FK -> users, indexed  |                                            |
| `key_digest`     | `string`    | NOT NULL, unique, indexed       | SHA256 hex digest of the actual key        |
| `name`           | `string`    | NOT NULL                       | Human-readable label for the key           |
| `last_used_at`   | `datetime`  | nullable                       | Tracks last usage                          |
| `monthly_usage`  | `integer`   | NOT NULL, default: 0           | Request count for current billing month    |
| `monthly_quota`  | `integer`   | NOT NULL                       | Maximum requests per month (tier-dependent)|
| `expires_at`     | `datetime`  | nullable                       | Optional expiration date                   |
| `active`         | `boolean`   | NOT NULL, default: true        | Soft-disable without deleting              |
| `created_at`     | `datetime`  | NOT NULL                       |                                            |
| `updated_at`     | `datetime`  | NOT NULL                       |                                            |

**Associations:**
- `belongs_to :user`

**Validations:**
- `validates :key_digest, presence: true, uniqueness: true`
- `validates :name, presence: true`
- `validates :monthly_quota, numericality: { greater_than: 0 }`

**Scopes:**
```ruby
scope :active, -> { where(active: true).where("expires_at IS NULL OR expires_at > ?", Time.current) }
```

**Business Rules:**
- The raw API key is generated once, shown to the user, and never stored. Only the SHA256 digest is persisted.
- Authentication: hash the incoming `X-API-Key` header with SHA256 and look up the digest.
- Monthly usage is incremented on each authenticated request via `increment_usage!`.
- Monthly quota is determined by the user's membership tier.
- Usage counter resets at the start of each billing month.
- Expired or inactive keys are excluded from authentication lookups.
- A user can have multiple API keys.

---

### WeatherCondition

Weather enrichment data fetched from external APIs after sighting submission.

**Table:** `weather_conditions`

| Column             | Type        | Constraints                     | Notes                                    |
|--------------------|-------------|---------------------------------|------------------------------------------|
| `id`               | `bigint`    | PK, auto-increment              |                                          |
| `sighting_id`      | `bigint`    | NOT NULL, FK -> sightings, unique, indexed | One weather record per sighting |
| `temperature_f`    | `decimal`   | nullable                        | Temperature in Fahrenheit                |
| `humidity_percent`  | `decimal`  | nullable                        | Relative humidity percentage             |
| `wind_speed_mph`   | `decimal`   | nullable                        | Wind speed in MPH                        |
| `wind_direction`   | `string`    | nullable                        | Cardinal direction (N, NE, E, etc.)      |
| `cloud_cover_percent` | `decimal`| nullable                        | Cloud cover percentage                   |
| `visibility_miles`  | `decimal`  | nullable                        | Visibility in miles                      |
| `precipitation`    | `string`    | nullable                        | Type of precipitation if any             |
| `moon_phase`       | `string`    | nullable                        | Moon phase at time of sighting           |
| `astronomical_twilight` | `string`| nullable                       | Twilight status (day, civil, nautical, astronomical, night) |
| `data_source`      | `string`    | NOT NULL                        | Which API provided the data              |
| `fetched_at`       | `datetime`  | NOT NULL                        | When the data was fetched                |
| `raw_response`     | `jsonb`     | nullable                        | Full API response for auditing           |
| `created_at`       | `datetime`  | NOT NULL                        |                                          |
| `updated_at`       | `datetime`  | NOT NULL                        |                                          |

**Associations:**
- `belongs_to :sighting`

**Validations:**
- `validates :data_source, presence: true`
- `validates :fetched_at, presence: true`
- `validates :sighting_id, uniqueness: true`

**Business Rules:**
- Weather data is fetched asynchronously via a background job after sighting creation.
- One weather record per sighting.
- `raw_response` stores the full API response as JSONB for auditability and re-processing.
- If the weather API is unavailable, the sighting is still saved; weather enrichment is best-effort.

---

### Witness

Individual witness records for a sighting (beyond the submitter).

**Table:** `witnesses`

| Column          | Type      | Constraints                     | Notes                                     |
|-----------------|-----------|----------------------------------|-------------------------------------------|
| `id`            | `bigint`  | PK, auto-increment               |                                           |
| `sighting_id`   | `bigint` | NOT NULL, FK -> sightings, indexed|                                           |
| `name`          | `string`  | nullable                         | Witness name (PII, handle with care)      |
| `contact_info`  | `string`  | nullable                         | PII, encrypted at rest                    |
| `statement`     | `text`    | nullable                         | Witness statement                         |
| `credibility_notes` | `text`| nullable                         | Investigator's credibility assessment     |
| `created_at`    | `datetime`| NOT NULL                         |                                           |
| `updated_at`    | `datetime`| NOT NULL                         |                                           |

**Associations:**
- `belongs_to :sighting`

**Validations:**
- (minimal; witnesses may be anonymous)

**Business Rules:**
- `name` and `contact_info` are PII and must never appear in logs.
- `contact_info` MUST be encrypted at rest using Rails encrypted attributes (`encrypts :contact_info`).
- Witnesses are optional; a sighting's `num_witnesses` count may not match the number of Witness records.
- Only investigators and admins can view witness contact information.

---

### AuditLog

Polymorphic audit trail for tracking changes to important records.

**Table:** `audit_logs`

| Column          | Type      | Constraints                      | Notes                                    |
|-----------------|-----------|----------------------------------|------------------------------------------|
| `id`            | `bigint`  | PK, auto-increment                |                                          |
| `auditable_type`| `string`  | NOT NULL, indexed (composite)     | Polymorphic: "Sighting", "Investigation" |
| `auditable_id`  | `bigint`  | NOT NULL, indexed (composite)     | ID of the audited record                 |
| `actor_type`    | `string`  | nullable, indexed (composite)     | Polymorphic: "User" or system            |
| `actor_id`      | `bigint`  | nullable, indexed (composite)     | ID of the actor (null for system actions)|
| `action`        | `string`  | NOT NULL                         | e.g., "create", "update", "delete", "status_change" |
| `changed_fields`| `jsonb`   | nullable                         | Hash of field names to [old, new] values |
| `metadata`      | `jsonb`   | nullable                         | Additional context (IP masked, request ID, etc.) |
| `created_at`    | `datetime`| NOT NULL                         |                                          |

**Associations:**
- `belongs_to :auditable, polymorphic: true`
- `belongs_to :actor, polymorphic: true, optional: true`

**Validations:**
- `validates :action, presence: true`

**Business Rules:**
- Audit logs are append-only; never update or delete.
- `changed_fields` stores a JSONB hash: `{ "status" => ["submitted", "under_review"] }`.
- `metadata` may include masked IP (last octet zeroed), request ID, user agent (for forensics).
- PII must never appear in `changed_fields` or `metadata` — redact or omit.
- System-initiated actions (e.g., background jobs) have `actor_type: nil, actor_id: nil`.
- Composite index on `(auditable_type, auditable_id)` and `(actor_type, actor_id)`.

---

### DeconflictionResult

Results from cross-referencing sightings against known flight paths, satellite passes, launches, etc.

**Table:** `deconfliction_results`

| Column            | Type        | Constraints                       | Notes                                     |
|-------------------|-------------|-----------------------------------|-------------------------------------------|
| `id`              | `bigint`    | PK, auto-increment                |                                           |
| `sighting_id`     | `bigint`    | NOT NULL, FK -> sightings, unique, indexed | One result set per sighting        |
| `aircraft_check`  | `jsonb`     | nullable                          | ADS-B / flight radar results              |
| `satellite_check` | `jsonb`     | nullable                          | Satellite pass results (CelesTrak, N2YO)  |
| `launch_check`    | `jsonb`     | nullable                          | Recent launch activity results            |
| `astronomical_check` | `jsonb`  | nullable                          | Celestial body positions                  |
| `weather_balloon_check` | `jsonb`| nullable                         | Known weather balloon launches            |
| `military_check`  | `jsonb`     | nullable                          | Known military activity (if available)    |
| `overall_status`  | `integer`   | NOT NULL, default: 0              | Enum: `pending` (0), `no_match` (1), `possible_match` (2), `confirmed_match` (3) |
| `confidence_score`| `decimal`   | nullable                          | 0.0 to 1.0 confidence score              |
| `notes`           | `text`      | nullable                          | Human-readable summary of findings        |
| `processed_at`    | `datetime`  | nullable                          | When deconfliction processing completed   |
| `created_at`      | `datetime`  | NOT NULL                          |                                           |
| `updated_at`      | `datetime`  | NOT NULL                          |                                           |

**Associations:**
- `belongs_to :sighting`

**Enums:**
```ruby
enum :overall_status, { pending: 0, no_match: 1, possible_match: 2, confirmed_match: 3 }, validate: true
```

**Validations:**
- `validates :overall_status, presence: true`
- `validates :sighting_id, uniqueness: true`
- `validates :confidence_score, numericality: { greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0 }, allow_nil: true`

**Aggregation:**
```ruby
# Called by each individual check job after writing its result.
# Uses pessimistic locking to prevent concurrent JSONB write races.
# Computes overall_status only when all checks have completed or timed out.
#
# @return [void]
def maybe_finalize!
  with_lock do
    return unless all_checks_complete_or_expired?
    update!(
      overall_status: compute_overall_status,
      confidence_score: compute_confidence_score,
      processed_at: Time.current
    )
  end
end
```

**Individual check writes MUST use column-specific SQL** to prevent JSONB race conditions:
```ruby
# Good: atomic column update (no read-modify-write race)
DeconflictionResult.where(id: result.id)
  .update_all(aircraft_check: check_data.to_json)

# Bad: loads full row, risks overwriting concurrent sibling writes
result.update!(aircraft_check: check_data)
```

**Business Rules:**
- Deconfliction runs asynchronously via background job after sighting submission.
- The `DeconflictionOrchestratorJob` enqueues all individual check jobs in parallel.
- Each individual check job writes to its own JSONB column using atomic SQL updates, then calls `maybe_finalize!`.
- `maybe_finalize!` uses `with_lock` to prevent race conditions when multiple checks complete simultaneously.
- `overall_status` and `confidence_score` are computed only after all checks complete (or a 10-minute deadline expires).
- Each `*_check` field stores structured JSONB with source-specific results.
- `confirmed_match` means the sighting is almost certainly a known object (aircraft, satellite, etc.).
- One deconfliction result per sighting.

---

### StripeWebhookEvent

Idempotency tracking for Stripe webhook events.

**Table:** `stripe_webhook_events`

| Column            | Type        | Constraints                    | Notes                               |
|-------------------|-------------|--------------------------------|--------------------------------------|
| `id`              | `bigint`    | PK, auto-increment             |                                      |
| `stripe_event_id` | `string`    | NOT NULL, unique, indexed       | Stripe's event ID (e.g., `evt_...`) |
| `event_type`      | `string`    | NOT NULL                       | e.g., `customer.subscription.updated`|
| `processed_at`    | `datetime`  | nullable                       | When the event was fully processed   |
| `created_at`      | `datetime`  | NOT NULL                       |                                      |
| `updated_at`      | `datetime`  | NOT NULL                       |                                      |

**Associations:**
- None (standalone idempotency table).

**Validations:**
- `validates :stripe_event_id, presence: true, uniqueness: true`
- `validates :event_type, presence: true`

**Business Rules:**
- Before processing a webhook, check if `stripe_event_id` already exists. If so, return `200 OK` immediately.
- Create the record before processing to prevent race conditions.
- `processed_at` is set after the event has been fully handled.
- Old events can be cleaned up periodically (e.g., events older than 90 days).

---

### PhysiologicalEffect

Physical effects reported by witnesses during or after a sighting.

**Table:** `physiological_effects`

| Column          | Type      | Constraints                      | Notes                                    |
|-----------------|-----------|----------------------------------|------------------------------------------|
| `id`            | `bigint`  | PK, auto-increment                |                                          |
| `sighting_id`   | `bigint` | NOT NULL, FK -> sightings, indexed |                                          |
| `effect_type`   | `string`  | NOT NULL                         | e.g., "nausea", "burns", "paralysis", "headache" |
| `description`   | `text`    | nullable                         | Detailed description of the effect       |
| `severity`      | `integer` | NOT NULL, default: 0             | Enum: `mild` (0), `moderate` (1), `severe` (2) |
| `onset`         | `string`  | nullable                         | When the effect started relative to sighting |
| `duration`      | `string`  | nullable                         | How long the effect lasted               |
| `created_at`    | `datetime`| NOT NULL                         |                                          |
| `updated_at`    | `datetime`| NOT NULL                         |                                          |

**Associations:**
- `belongs_to :sighting`

**Enums:**
```ruby
enum :severity, { mild: 0, moderate: 1, severe: 2 }, validate: true
```

**Validations:**
- `validates :effect_type, presence: true`
- `validates :severity, presence: true`

---

### PsychologicalEffect

Psychological/cognitive effects reported by witnesses.

**Table:** `psychological_effects`

| Column          | Type      | Constraints                      | Notes                                    |
|-----------------|-----------|----------------------------------|------------------------------------------|
| `id`            | `bigint`  | PK, auto-increment                |                                          |
| `sighting_id`   | `bigint` | NOT NULL, FK -> sightings, indexed |                                          |
| `effect_type`   | `string`  | NOT NULL                         | e.g., "time_loss", "anxiety", "compulsion", "vivid_dreams" |
| `description`   | `text`    | nullable                         | Detailed description                     |
| `severity`      | `integer` | NOT NULL, default: 0             | Enum: `mild` (0), `moderate` (1), `severe` (2) |
| `onset`         | `string`  | nullable                         | When the effect started                  |
| `duration`      | `string`  | nullable                         | How long the effect lasted               |
| `created_at`    | `datetime`| NOT NULL                         |                                          |
| `updated_at`    | `datetime`| NOT NULL                         |                                          |

**Associations:**
- `belongs_to :sighting`

**Enums:**
```ruby
enum :severity, { mild: 0, moderate: 1, severe: 2 }, validate: true
```

**Validations:**
- `validates :effect_type, presence: true`
- `validates :severity, presence: true`

---

### EquipmentEffect

Effects on electronic or mechanical equipment during a sighting.

**Table:** `equipment_effects`

| Column          | Type      | Constraints                      | Notes                                    |
|-----------------|-----------|----------------------------------|------------------------------------------|
| `id`            | `bigint`  | PK, auto-increment                |                                          |
| `sighting_id`   | `bigint` | NOT NULL, FK -> sightings, indexed |                                          |
| `equipment_type`| `string`  | NOT NULL                         | e.g., "car_engine", "radio", "phone", "compass" |
| `effect_type`   | `string`  | NOT NULL                         | e.g., "malfunction", "interference", "shutdown", "drain" |
| `description`   | `text`    | nullable                         | Detailed description                     |
| `created_at`    | `datetime`| NOT NULL                         |                                          |
| `updated_at`    | `datetime`| NOT NULL                         |                                          |

**Associations:**
- `belongs_to :sighting`

**Validations:**
- `validates :equipment_type, presence: true`
- `validates :effect_type, presence: true`

---

### EnvironmentalTrace

Physical traces or environmental changes observed at the sighting location.

**Table:** `environmental_traces`

| Column          | Type      | Constraints                      | Notes                                    |
|-----------------|-----------|----------------------------------|------------------------------------------|
| `id`            | `bigint`  | PK, auto-increment                |                                          |
| `sighting_id`   | `bigint` | NOT NULL, FK -> sightings, indexed |                                          |
| `trace_type`    | `string`  | NOT NULL                         | e.g., "ground_marking", "radiation", "scorching", "magnetic_anomaly" |
| `description`   | `text`    | nullable                         | Detailed description                     |
| `location`      | `st_point`| geographic, SRID 4326, nullable  | Specific location of the trace if different from sighting |
| `measured_value` | `string` | nullable                         | Measurement reading if applicable        |
| `measurement_unit` | `string`| nullable                        | Unit of measurement                      |
| `created_at`    | `datetime`| NOT NULL                         |                                          |
| `updated_at`    | `datetime`| NOT NULL                         |                                          |

**Associations:**
- `belongs_to :sighting`

**Validations:**
- `validates :trace_type, presence: true`

**Business Rules:**
- `location` is optional; defaults to the parent sighting's location if not specified.
- If `measured_value` is present, `measurement_unit` should also be present.
- Traces with location use PostGIS geography points (SRID 4326) with GiST index.

---

## Entity Relationship Summary

```
User 1--* Sighting (submitter_id)
User 1--* Investigation (investigator_id)
User 1--1 Membership
User 1--* ApiKey
User 1--* AuditLog (as actor, polymorphic)

Sighting *--1 Shape
Sighting 1--1 Investigation (optional)
Sighting 1--* Evidence
Sighting 1--* Witness
Sighting 1--1 WeatherCondition
Sighting 1--1 DeconflictionResult
Sighting 1--* PhysiologicalEffect
Sighting 1--* PsychologicalEffect
Sighting 1--* EquipmentEffect
Sighting 1--* EnvironmentalTrace
Sighting 1--* AuditLog (as auditable, polymorphic)

Investigation 1--* Evidence
Investigation 1--* AuditLog (as auditable, polymorphic)

Evidence *--1 User (submitted_by_id)

Membership 1--* AuditLog (as auditable, polymorphic)

StripeWebhookEvent (standalone)
```

## Key Design Decisions

1. **User role vs. Membership tier:** Role controls what actions a user can perform (RBAC). Tier controls what features/limits apply (subscription). They are independent axes checked in Pundit policies.
2. **PostGIS geography over geometry:** Geography columns use the Earth's actual curvature for distance calculations, which is essential for a global sighting database. SRID 4326 (WGS 84) is the standard.
3. **Separate observed_timezone:** Storing UTC in `observed_at` with the original timezone in `observed_timezone` allows accurate time display in the observer's local time while enabling consistent querying in UTC.
4. **Polymorphic audit logs:** A single audit table tracks changes across all important models, simplifying compliance and forensics.
5. **Effect models as separate tables:** PhysiologicalEffect, PsychologicalEffect, EquipmentEffect, and EnvironmentalTrace are separate models (not STI or JSONB) to allow proper validation, querying, and future schema evolution.
6. **Stripe idempotency table:** StripeWebhookEvent prevents duplicate processing of webhooks, which Stripe may retry.
7. **Evidence dual-parent:** Evidence can belong to either a Sighting or an Investigation but not both, allowing evidence collection at both stages of the workflow.
