# syntax=docker/dockerfile:1
# check=error=true

# Hardened multi-stage Dockerfile for APRS Platform
# Base: Chainguard Wolfi (zero CVEs, daily rebuilds, glibc)
# NOTE: Free tier is :latest only — cannot pin Ruby version.
# This is the one accepted exception to our version pinning policy.

# === Builder stage: has shell, apk, build tools ===
FROM cgr.dev/chainguard/ruby:latest-dev AS build

WORKDIR /rails

# Install build dependencies for native gems (pg, nokogiri, etc.)
RUN apk add --no-cache \
      build-base \
      git \
      postgresql-dev \
      yaml-dev \
      vips-dev \
      pkgconf

ENV RAILS_ENV="production" \
    BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development:test"

COPY Gemfile Gemfile.lock ./
RUN bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git && \
    bundle exec bootsnap precompile --gemfile

COPY . .

RUN bundle exec bootsnap precompile app/ lib/
RUN SECRET_KEY_BASE_DUMMY=1 ./bin/rails assets:precompile

# Install runtime-only libraries (no -dev headers) for copying to final stage
RUN apk add --no-cache \
      postgresql-client \
      libvips \
      jemalloc

# === Runtime stage: distroless, no shell, no package manager ===
FROM cgr.dev/chainguard/ruby:latest

WORKDIR /rails

ENV RAILS_ENV="production" \
    BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development:test" \
    RAILS_LOG_TO_STDOUT="1" \
    RAILS_SERVE_STATIC_FILES="1"

# Copy runtime shared libraries from builder (distroless has no package manager)
COPY --from=build /usr/lib/libpq* /usr/lib/
COPY --from=build /usr/lib/libvips* /usr/lib/
COPY --from=build /usr/lib/libjemalloc* /usr/lib/

# Copy built artifacts: gems and application
# Chainguard :latest already runs as nonroot (UID 65532)
COPY --from=build "${BUNDLE_PATH}" "${BUNDLE_PATH}"
COPY --from=build /rails /rails

# Ruby-based health check (no curl/shell in distroless)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["ruby", "-e", "require 'net/http'; Net::HTTP.get(URI('http://localhost:3000/up'))"]

ENTRYPOINT ["/rails/bin/docker-entrypoint"]

EXPOSE 3000
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
