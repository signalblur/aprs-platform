# A06 — Vulnerable and Outdated Components

## Overview

Vulnerable and Outdated Components (OWASP 2021 A06) refers to the risk introduced by using software components -- libraries, frameworks, runtime environments, and infrastructure -- that contain known security vulnerabilities. Modern web applications like APRS depend on dozens of direct dependencies and hundreds of transitive dependencies. Each one is a potential entry point for attackers if it contains a known CVE that has not been patched. Unlike application-level vulnerabilities that require specific exploitation knowledge, component vulnerabilities are often weaponized quickly because they affect thousands of applications simultaneously.

For the APRS platform, this risk is particularly acute because the dependency tree spans multiple ecosystems: Ruby gems (40+ direct dependencies in the Gemfile), JavaScript packages (via importmap-rails), the Ruby runtime itself, the Rails framework, PostgreSQL with the PostGIS extension, the Chainguard container base image, and GitHub Actions used in CI/CD pipelines. Each of these has its own release cadence, security advisory process, and patching timeline. A vulnerability in any one component -- such as a deserialization flaw in a JSON parser gem, a SQL injection in the PostGIS adapter, or a prototype pollution in a JavaScript dependency -- can compromise the entire application.

The challenge is not just identifying vulnerable components but establishing a continuous process for monitoring, triaging, and patching them. Tools like `bundler-audit` (for Ruby gems), `importmap audit` (for JavaScript), and `trivy` (for container images) automate detection, but they only work if they are run regularly, their advisory databases are kept current, and their findings are acted upon promptly. Without a security patch policy that defines response times for critical, high, and medium severity CVEs, even a well-instrumented project will accumulate technical debt that eventually becomes exploitable.

## APRS-Specific Attack Surface

- **Gemfile dependencies**: 40+ direct gems including security-critical ones (devise, stripe, pg, rgeo, puma, image_processing)
- **Transitive dependencies**: Each direct gem pulls in its own dependency tree; vulnerabilities in nested gems are easy to miss
- **Ruby runtime**: Ruby 3.4.8 must be kept current; minor versions include security patches
- **Rails framework**: Rails 8.1.x receives security patches; end-of-life Rails versions get no fixes
- **importmap-rails JavaScript dependencies**: Pinned CDN URLs for JavaScript libraries must be audited
- **PostgreSQL and PostGIS**: Database server and spatial extension have separate CVE streams
- **Container base image**: `cgr.dev/chainguard/ruby:latest` Wolfi packages must be rebuilt regularly
- **CI/CD GitHub Actions**: Action versions pinned by tag can be hijacked; SHA pinning is required
- **Development/test gems**: debug, web-console, factory_bot can introduce vulnerabilities in CI if not isolated
- **image_processing gem**: Depends on libvips/ImageMagick which have a long history of CVEs in image parsing

## Examples

### Basic Level

#### Example 1: Running `bundler-audit` With a Stale Advisory Database

**Source:** https://github.com/rubysec/bundler-audit
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile (development/test group)
group :development, :test do
  gem "bundler-audit", require: false
end

# .github/workflows/ci.yml (partial)
# bundler-audit is run but the advisory database is never updated.
# New CVEs published after the last `bundle audit update` will not
# be detected, creating a false sense of security.
# jobs:
#   security:
#     steps:
#       - run: bundle exec bundler-audit check
#         # Missing: bundle exec bundler-audit update
```

```bash
# Developer runs audit locally but skips the update step
$ bundle exec bundler-audit check
# Reports "No vulnerabilities found" even though the database
# is 3 months old and missing recent advisories.
```

**Secure Fix:**
```yaml
# .github/workflows/ci.yml
# Always update the advisory database before running the audit.
# Fail the build if any vulnerabilities are found.
name: Security Audit
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * 1"  # Weekly Monday 6 AM UTC

jobs:
  bundler-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: "3.4.8"
          bundler-cache: true

      - name: Update advisory database
        run: bundle exec bundler-audit update

      - name: Run bundler-audit
        run: bundle exec bundler-audit check --format json --output audit-results.json || true

      - name: Fail on vulnerabilities
        run: |
          if bundle exec bundler-audit check; then
            echo "No vulnerabilities found"
          else
            echo "::error::Vulnerable gems detected. See audit results."
            exit 1
          fi
```

```ruby
# lib/tasks/security.rake
# Rake task for local development that always updates first.
namespace :security do
  desc "Run bundler-audit with fresh advisory database"
  task audit: :environment do
    system("bundle exec bundler-audit update") || abort("Failed to update advisory DB")
    system("bundle exec bundler-audit check") || abort("Vulnerabilities found!")
  end
end
```

#### Example 2: Known Vulnerable Gem Version in Gemfile.lock

**Source:** https://www.cvedetails.com/vulnerability-list/vendor_id-22225/product_id-83498/Puma-Puma.html
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile
# Version constraint is too loose, allowing installation of versions
# with known CVEs. The Gemfile.lock may pin a vulnerable version
# that persists across deployments.
gem "puma", ">= 5.0"           # allows any version >= 5.0
gem "image_processing", "~> 1.2"  # allows 1.2.x through 1.x.y
gem "devise"                       # no version constraint at all
gem "nokogiri"                     # transitive dep, no direct pin
```

```
# Gemfile.lock (excerpt showing hypothetical vulnerable versions)
puma (5.6.7)      # hypothetical: CVE in HTTP request smuggling
nokogiri (1.14.0) # hypothetical: CVE in libxml2 parsing
```

**Secure Fix:**
```ruby
# Gemfile
# Pin to minimum safe versions that include security patches.
# Use pessimistic version constraints (~>) to allow patch updates
# while preventing major/minor version jumps.
gem "puma", "~> 6.5"                # latest stable with security fixes
gem "image_processing", "~> 1.13"   # latest 1.x with security fixes
gem "devise", "~> 4.9"              # pinned to known-good minor
gem "nokogiri", "~> 1.16"           # pinned to version with patched libxml2

# After updating Gemfile:
# 1. Run: bundle update puma image_processing devise nokogiri
# 2. Run: bundle exec bundler-audit check
# 3. Run: bundle exec rspec (full test suite)
# 4. Commit both Gemfile and Gemfile.lock together
```

#### Example 3: Outdated Ruby Version With Known CVEs

**Source:** https://www.ruby-lang.org/en/news/
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile
ruby "3.2.0"  # end-of-life or outdated Ruby with known CVEs

# .ruby-version
# 3.2.0

# Dockerfile
FROM ruby:3.2.0  # old base image with unpatched system libraries
```

**Secure Fix:**
```ruby
# Gemfile
# Use the latest stable patch release of the current Ruby series.
# Ruby 3.4.x is the current stable series for APRS.
ruby "3.4.8"

# .ruby-version
# 3.4.8

# Dockerfile (using Chainguard which tracks latest patches)
FROM cgr.dev/chainguard/ruby:latest AS runtime
# Chainguard images are rebuilt nightly with latest security patches
```

```yaml
# .github/workflows/ci.yml
# Pin Ruby version in CI to match production exactly.
# Dependabot or Renovate should open PRs for Ruby version bumps.
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: "3.4.8"  # must match Gemfile and .ruby-version
```

### Intermediate Level

#### Example 4: Unpinned GitHub Actions Versions (Tag-Based Injection Risk)

**Source:** https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions
**Status:** [VERIFIED]

**Vulnerable Code:**
```yaml
# .github/workflows/ci.yml
# Actions pinned by mutable tag. If the action maintainer's account
# is compromised, the attacker can move the v4 tag to a malicious
# commit. This is a supply chain attack vector.
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4           # mutable tag!
      - uses: ruby/setup-ruby@v1            # mutable tag!
      - uses: actions/cache@v4              # mutable tag!
      - uses: docker/build-push-action@v5   # mutable tag!
```

**Secure Fix:**
```yaml
# .github/workflows/ci.yml
# Actions pinned by full SHA256 commit hash. Even if the maintainer's
# account is compromised, the attacker cannot change the code that runs
# without changing the hash. Comment includes the tag for readability.
name: CI
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read  # principle of least privilege

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683     # v4.2.2
      - uses: ruby/setup-ruby@a4effe49ee010ee53e1cf38f4be923e1a1d8b28f     # v1.207.0
      - uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684       # v4.2.3

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683     # v4.2.2
      - uses: ruby/setup-ruby@a4effe49ee010ee53e1cf38f4be923e1a1d8b28f     # v1.207.0
        with:
          ruby-version: "3.4.8"
          bundler-cache: true
      - name: Bundler Audit
        run: bundle exec bundler-audit update && bundle exec bundler-audit check
      - name: Brakeman
        run: bundle exec brakeman --no-pager -q
```

```yaml
# .github/dependabot.yml
# Configure Dependabot to monitor GitHub Actions versions and open
# PRs when new versions are available with SHA updates.
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "infra:"

  - package-ecosystem: "bundler"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "security:"
    labels:
      - "dependencies"
      - "security"
```

#### Example 5: Vulnerable Transitive Dependencies Not Detected

**Source:** https://bundler.io/guides/bundler_2_upgrade.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile
# Direct dependencies look fine, but they pull in transitive
# dependencies that may have known CVEs. For example:
# - image_processing -> ruby-vips -> libvips (C library CVEs)
# - devise -> bcrypt -> bcrypt-ruby (C extension CVEs)
# - rgeo -> geos (C library CVEs)
# - nokogiri -> libxml2, libxslt (frequent CVEs)

gem "image_processing", "~> 1.2"   # pulls in ruby-vips
gem "devise"                        # pulls in bcrypt, warden, orm_adapter
gem "rgeo"                          # pulls in native geos library
gem "pg"                            # pulls in libpq
```

```bash
# Developer only checks direct gems, missing transitive vulnerabilities
$ bundle exec bundler-audit check
# Only checks gems in Gemfile.lock, not native C library dependencies
# Does NOT check: libvips, libxml2, libpq, geos system libraries
```

**Secure Fix:**
```yaml
# .github/workflows/security-scan.yml
# Comprehensive security scanning that covers direct gems, transitive
# gems, and native library dependencies in the container image.
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * *"  # daily at 6 AM UTC

jobs:
  gem-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: ruby/setup-ruby@a4effe49ee010ee53e1cf38f4be923e1a1d8b28f
        with:
          ruby-version: "3.4.8"
          bundler-cache: true
      - name: Update and run bundler-audit
        run: |
          bundle exec bundler-audit update
          bundle exec bundler-audit check

  container-scan:
    runs-on: ubuntu-latest
    needs: [gem-audit]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Build container image
        run: docker build -t aprs-platform:scan .
      - name: Scan with Trivy
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v trivy-cache:/root/.cache/ \
            aquasec/trivy:latest image \
            --exit-code 1 \
            --severity CRITICAL,HIGH \
            --ignore-unfixed \
            aprs-platform:scan
```

```ruby
# lib/tasks/security.rake
# Comprehensive security rake task that checks all dependency layers.
namespace :security do
  desc "Full security audit: gems, Brakeman, and dependency check"
  task full_audit: :environment do
    puts "=== Bundler Audit (Ruby gems) ==="
    system("bundle exec bundler-audit update") || warn("Advisory DB update failed")
    unless system("bundle exec bundler-audit check")
      abort("FAIL: Vulnerable gems detected")
    end

    puts "\n=== Brakeman (Static Analysis) ==="
    unless system("bundle exec brakeman --no-pager -q")
      abort("FAIL: Brakeman found security issues")
    end

    puts "\n=== Gemfile.lock Staleness Check ==="
    lock_age = (Time.now - File.mtime("Gemfile.lock")) / 86_400
    if lock_age > 30
      warn("WARNING: Gemfile.lock is #{lock_age.to_i} days old. Run `bundle update`.")
    end

    puts "\nAll security checks passed."
  end
end
```

#### Example 6: Stale Gemfile.lock Not Regularly Updated

**Source:** https://bundler.io/man/bundle-update.1.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile.lock is 6 months old. Even though the Gemfile constraints
# allow newer versions, `bundle install` respects the lock file and
# installs the exact (potentially vulnerable) versions specified.
#
# The lock file will only update when someone explicitly runs
# `bundle update`, which may never happen if there is no policy.

# Gemfile
gem "rails", "~> 8.1.2"  # allows 8.1.3, 8.1.4, etc.
# But Gemfile.lock still pins 8.1.2 from 6 months ago
```

**Secure Fix:**
```yaml
# .github/dependabot.yml
# Dependabot opens PRs weekly for gem updates, ensuring the lock file
# stays current. Security updates are prioritized.
version: 2
updates:
  - package-ecosystem: "bundler"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "security:"
      include: "scope"
    labels:
      - "dependencies"
    # Group patch updates to reduce PR noise
    groups:
      patch-updates:
        update-types:
          - "patch"
      minor-updates:
        update-types:
          - "minor"
    # Security updates bypass normal scheduling
    security-updates:
      open-pull-requests-limit: 20
```

```ruby
# doc/SECURITY_PATCH_POLICY.md (referenced, not created)
# Security Patch Response Times:
# - CRITICAL (CVSS >= 9.0): Patch within 24 hours
# - HIGH (CVSS 7.0-8.9): Patch within 72 hours
# - MEDIUM (CVSS 4.0-6.9): Patch within 2 weeks
# - LOW (CVSS < 4.0): Patch in next scheduled update

# lib/tasks/security.rake
namespace :security do
  desc "Check for available gem updates (security-relevant)"
  task :check_updates do
    puts "=== Available Gem Updates ==="
    system("bundle outdated --only-explicit --strict")

    puts "\n=== Security-Specific Updates ==="
    system("bundle exec bundler-audit update && bundle exec bundler-audit check")
  end
end
```

### Advanced Level

#### Example 7: Container Base Image With Unpatched System Libraries

**Source:** https://edu.chainguard.dev/chainguard/chainguard-images/about/images-features/
**Status:** [VERIFIED]

**Vulnerable Code:**
```dockerfile
# Dockerfile
# Using a community Ruby image that includes hundreds of system packages,
# many of which may have known CVEs. The image is not regularly rebuilt,
# so even if upstream packages are patched, this image retains the
# vulnerable versions.
FROM ruby:3.4.8-slim
# This image includes: openssl, libxml2, libxslt, zlib, libc6, etc.
# Trivy scan may show 50+ CVEs in system packages alone.

WORKDIR /app
COPY . .
RUN bundle install
CMD ["bin/rails", "server"]
```

```bash
# Scanning the community image reveals many system-level CVEs
$ trivy image ruby:3.4.8-slim
# Total: 147 (CRITICAL: 3, HIGH: 27, MEDIUM: 89, LOW: 28)
# Most are in system libraries that Rails depends on transitively.
```

**Secure Fix:**
```dockerfile
# Dockerfile
# Chainguard images are rebuilt nightly with the latest Wolfi packages.
# They contain only the minimal set of packages needed to run Ruby,
# dramatically reducing the CVE surface. The -dev variant is only
# used in the builder stage.
FROM cgr.dev/chainguard/ruby:latest-dev AS builder
WORKDIR /app

# Install build dependencies only in builder stage
COPY Gemfile Gemfile.lock ./
RUN bundle config set --local deployment true && \
    bundle config set --local without 'development test' && \
    bundle install --jobs 4 --retry 3

COPY . .
RUN SECRET_KEY_BASE_DUMMY=1 bundle exec rails assets:precompile

# Runtime stage: minimal image, no build tools, no shell
FROM cgr.dev/chainguard/ruby:latest
WORKDIR /app

COPY --from=builder /app /app

USER nonroot
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["ruby", "-e", "require 'net/http'; Net::HTTP.get(URI('http://localhost:3000/up'))"]

CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
```

```yaml
# .github/workflows/container-security.yml
# Automated container image scanning on every build and weekly schedule.
name: Container Security
on:
  push:
    branches: [main]
    paths:
      - "Dockerfile"
      - "Gemfile.lock"
  schedule:
    - cron: "0 4 * * 1"  # weekly Monday 4 AM UTC

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Build image
        run: docker build -t aprs-platform:${{ github.sha }} .
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@18f2510ee396bbf400402947e795cb3a0efc3f8a  # v0.28.0
        with:
          image-ref: "aprs-platform:${{ github.sha }}"
          format: "sarif"
          output: "trivy-results.sarif"
          severity: "CRITICAL,HIGH"
          exit-code: "1"
      - name: Upload scan results
        uses: github/codeql-action/upload-sarif@4dd16135b69cb9d2e9f48c5a10ffb36e4e6b3113  # v3
        if: always()
        with:
          sarif_file: "trivy-results.sarif"
```

#### Example 8: image_processing Gem With Vulnerable Native Library Backend

**Source:** https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile
gem "image_processing", "~> 1.2"
# image_processing depends on either ImageMagick (via MiniMagick) or
# libvips (via ruby-vips). Both have extensive CVE histories:
# - ImageMagick: CVE-2023-34151, CVE-2023-1289 (arbitrary code execution)
# - libvips: Generally safer, but older versions have buffer overflows

# app/models/evidence.rb
# Processing user-uploaded images with a potentially vulnerable backend
class Evidence < ApplicationRecord
  has_one_attached :file do |attachable|
    attachable.variant :thumb, resize_to_limit: [200, 200]
    attachable.variant :medium, resize_to_limit: [800, 800]
  end
  # No specification of which processor to use
  # No limits on input image dimensions
end
```

**Secure Fix:**
```ruby
# Gemfile
# Pin image_processing to latest version and explicitly require vips
# (not ImageMagick, which has a larger CVE surface).
gem "image_processing", "~> 1.13"
gem "ruby-vips", "~> 2.2"  # explicit pin, prefer vips over ImageMagick

# config/initializers/image_processing.rb
# Force vips backend and configure security limits for image processing.
# This prevents processing of maliciously crafted images designed to
# exploit ImageMagick vulnerabilities.
require "image_processing/vips"

# Set global limits for image processing to prevent denial of service
# via decompression bombs or extremely large images.
Vips.concurrency_set(2)    # limit concurrent processing threads
Vips.cache_set_max(0)      # disable cache to reduce memory usage

# app/models/evidence.rb
class Evidence < ApplicationRecord
  has_one_attached :file do |attachable|
    attachable.variant :thumb, resize_to_limit: [200, 200], saver: { quality: 80 }
    attachable.variant :medium, resize_to_limit: [800, 800], saver: { quality: 85 }
  end

  MAX_IMAGE_DIMENSION = 10_000  # pixels
  MAX_IMAGE_MEGAPIXELS = 40     # prevent decompression bombs

  validate :image_dimensions_within_limits, if: -> { file.attached? && image? }

  private

  # @return [Boolean] whether the attached file is an image
  def image?
    file.blob.content_type.start_with?("image/")
  end

  # @return [void]
  def image_dimensions_within_limits
    return unless file.blob.analyzed?

    metadata = file.blob.metadata
    width = metadata[:width].to_i
    height = metadata[:height].to_i

    if width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION
      errors.add(:file, "dimensions exceed maximum of #{MAX_IMAGE_DIMENSION}px")
    end

    megapixels = (width * height) / 1_000_000.0
    if megapixels > MAX_IMAGE_MEGAPIXELS
      errors.add(:file, "resolution exceeds maximum of #{MAX_IMAGE_MEGAPIXELS} megapixels")
    end
  end
end
```

#### Example 9: importmap JavaScript Dependencies Without Integrity Checks

**Source:** https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# config/importmap.rb
# JavaScript dependencies pinned to CDN URLs without integrity hashes.
# If the CDN is compromised or serves a modified file, the browser
# will execute malicious JavaScript in the context of the APRS application.
pin "application"
pin "@hotwired/turbo-rails", to: "turbo.min.js"
pin "@hotwired/stimulus", to: "stimulus.min.js"
pin "chartkick", to: "https://cdn.jsdelivr.net/npm/chartkick@5.0.1/dist/chartkick.min.js"
pin "Chart.bundle", to: "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
# No integrity hashes, no local fallback
```

**Secure Fix:**
```ruby
# config/importmap.rb
# All JavaScript dependencies are vendored locally (not loaded from CDN)
# or pinned with integrity hashes. This prevents CDN compromise from
# injecting malicious code.
pin "application"
pin "@hotwired/turbo-rails", to: "turbo.min.js"
pin "@hotwired/stimulus", to: "stimulus.min.js"

# Vendor third-party JS locally instead of loading from CDN
# Run: bin/importmap pin chartkick --download
pin "chartkick", to: "vendor/chartkick.js"      # vendored locally
pin "Chart.bundle", to: "vendor/chart.umd.js"    # vendored locally
```

```bash
# Vendor JavaScript dependencies locally instead of using CDN
# This eliminates the CDN as a trust boundary entirely.
$ bin/importmap pin chartkick --download
$ bin/importmap pin chart.js --download

# Verify integrity of vendored files
$ shasum -a 384 vendor/javascript/chartkick.js
# Record this hash and verify it matches the expected value from
# the package registry (npmjs.com)
```

```yaml
# .github/workflows/ci.yml (additional step)
# Audit importmap pins for known vulnerabilities and verify
# vendored files have not been tampered with.
- name: Audit importmap dependencies
  run: |
    bin/importmap audit
    # Verify vendored file checksums
    shasum -c vendor/javascript/checksums.txt
```

#### Example 10: Missing Security Patch Policy and No Automated Monitoring

**Source:** https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# No automated dependency monitoring configured.
# No Dependabot, no Renovate, no scheduled security scans.
# No defined SLA for patching critical vulnerabilities.
# Security patches are applied "when someone notices."

# Gemfile
# Last updated: 6 months ago
# No one knows if any gems have published security advisories since then
gem "rails", "~> 8.1.2"
gem "devise", "~> 4.9"
gem "puma", ">= 5.0"
gem "nokogiri"  # not even pinned to a version
```

**Secure Fix:**
```yaml
# .github/dependabot.yml
# Comprehensive Dependabot configuration covering all dependency ecosystems.
version: 2
updates:
  # Ruby gems
  - package-ecosystem: "bundler"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "06:00"
      timezone: "America/New_York"
    open-pull-requests-limit: 15
    commit-message:
      prefix: "security:"
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security-review"
    groups:
      rails-ecosystem:
        patterns:
          - "rails"
          - "railties"
          - "actionpack"
          - "activerecord"
          - "activesupport"
          - "activestorage"
          - "actionmailer"
      security-gems:
        patterns:
          - "devise"
          - "pundit"
          - "stripe"
          - "bcrypt"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "infra:"

  # Container base image (Dockerfile)
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "infra:"
```

```yaml
# .github/workflows/scheduled-security.yml
# Scheduled security scans that run independently of code changes.
# This catches newly published CVEs affecting existing dependencies.
name: Scheduled Security Scan
on:
  schedule:
    - cron: "0 6 * * *"  # daily at 6 AM UTC
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  gem-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: ruby/setup-ruby@a4effe49ee010ee53e1cf38f4be923e1a1d8b28f
        with:
          ruby-version: "3.4.8"
          bundler-cache: true
      - name: Update and run bundler-audit
        run: |
          bundle exec bundler-audit update
          bundle exec bundler-audit check
      - name: Run Brakeman
        run: bundle exec brakeman --no-pager -q

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Build image
        run: docker build -t aprs-platform:scan .
      - name: Trivy scan
        uses: aquasecurity/trivy-action@18f2510ee396bbf400402947e795cb3a0efc3f8a
        with:
          image-ref: "aprs-platform:scan"
          format: "sarif"
          output: "trivy-results.sarif"
          severity: "CRITICAL,HIGH"
      - name: Upload results
        uses: github/codeql-action/upload-sarif@4dd16135b69cb9d2e9f48c5a10ffb36e4e6b3113
        if: always()
        with:
          sarif_file: "trivy-results.sarif"

  notify-on-failure:
    runs-on: ubuntu-latest
    needs: [gem-audit, container-scan]
    if: failure()
    steps:
      - name: Notify security team
        run: |
          echo "::error::Security scan failed. Review results immediately."
          # Integration with Slack, PagerDuty, or email notification
```

## Checklist

- [ ] `bundler-audit` is in the Gemfile and runs in CI on every push
- [ ] `bundler-audit update` runs before `bundler-audit check` to ensure fresh advisory database
- [ ] `brakeman` runs in CI on every push with `--no-pager` flag
- [ ] All direct gems in Gemfile use pessimistic version constraints (`~>`)
- [ ] No gem is unpinned (bare `gem "name"` without version constraint)
- [ ] `Gemfile.lock` is committed to version control and updated at least monthly
- [ ] Ruby version in Gemfile, `.ruby-version`, and Dockerfile all match
- [ ] Ruby version is the latest patch release of the current stable series
- [ ] Rails version is the latest patch release receiving security updates
- [ ] Dependabot or Renovate is configured for the `bundler` package ecosystem
- [ ] Dependabot or Renovate is configured for `github-actions` ecosystem
- [ ] Dependabot or Renovate is configured for `docker` ecosystem
- [ ] GitHub Actions are pinned by full SHA, not by mutable tag
- [ ] A comment with the tag version accompanies each SHA-pinned action
- [ ] Scheduled security scans run at least weekly (daily preferred)
- [ ] Container image is scanned with Trivy before deployment
- [ ] Container base image is Chainguard (Wolfi) or equivalent minimal image
- [ ] Container base image is rebuilt/pulled regularly to pick up OS-level patches
- [ ] `image_processing` gem uses vips backend, not ImageMagick
- [ ] Image dimension and megapixel limits are enforced before processing
- [ ] importmap JavaScript dependencies are vendored locally or integrity-checked
- [ ] `bin/importmap audit` runs in CI
- [ ] A security patch response policy exists with defined SLAs by severity
- [ ] Critical CVEs (CVSS >= 9.0) have a 24-hour patch SLA
- [ ] High CVEs (CVSS 7.0-8.9) have a 72-hour patch SLA
- [ ] Transitive dependencies are included in vulnerability scanning (not just direct gems)
- [ ] Native C library dependencies (libvips, libxml2, libpq, geos) are tracked for CVEs via container scanning
- [ ] No development-only gems (web-console, debug) are loaded in production
- [ ] PostgreSQL and PostGIS versions are tracked and updated for security patches
