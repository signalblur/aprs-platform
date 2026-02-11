# frozen_string_literal: true

# File-based evidence attached to a UAP sighting report.
#
# Stores metadata about evidence files (photos, videos, audio, documents)
# with the actual file managed by Active Storage. Validates content type
# against an allowlist and verifies magic bytes to prevent type spoofing.
#
# @attr [Sighting] sighting the parent sighting report
# @attr [User] submitted_by the user who uploaded this evidence
# @attr [Integer] evidence_type the category of evidence (photo, video, audio, document, other)
# @attr [String, nil] description optional description of the evidence
class Evidence < ApplicationRecord
  # Maximum file size allowed for evidence uploads (100 MB).
  MAX_FILE_SIZE = 100.megabytes

  # Allowed content types for evidence file uploads.
  ALLOWED_CONTENT_TYPES = %w[
    image/jpeg
    image/png
    image/webp
    video/mp4
    video/mpeg
    audio/wav
    application/pdf
  ].freeze

  # Magic byte signatures for file type verification.
  # Maps content type prefixes to their expected byte patterns.
  MAGIC_BYTES = {
    "image/jpeg" => [ "\xFF\xD8\xFF".b ],
    "image/png" => [ "\x89PNG".b ],
    "image/webp" => [ "RIFF".b ],
    "video/mp4" => [ "\x00\x00\x00".b, "ftyp".b ],
    "video/mpeg" => [ "\x00\x00\x01\xBA".b, "\x00\x00\x01\xB3".b ],
    "audio/wav" => [ "RIFF".b ],
    "application/pdf" => [ "%PDF".b ]
  }.freeze

  belongs_to :sighting, optional: true
  belongs_to :investigation, optional: true
  belongs_to :submitted_by, class_name: "User", inverse_of: :evidences

  has_one_attached :file

  enum :evidence_type, { photo: 0, video: 1, audio: 2, document: 3, other: 4 },
       default: :photo, validate: true

  validate :acceptable_file, if: -> { file.attached? }
  validate :exactly_one_parent

  private

  # Validates that evidence belongs to exactly one parent (sighting XOR investigation).
  #
  # @return [void]
  def exactly_one_parent
    has_sighting = sighting_id.present? || sighting.present?
    has_investigation = investigation_id.present? || investigation.present?

    if has_sighting && has_investigation
      errors.add(:base, "must belong to either a sighting or an investigation, not both")
    elsif !has_sighting && !has_investigation
      errors.add(:base, "must belong to either a sighting or an investigation")
    end
  end

  # Validates the attached file for content type, magic bytes, and size.
  #
  # @return [void]
  def acceptable_file
    validate_content_type
    validate_magic_bytes
    validate_file_size
  end

  # Validates that the file content type is in the allowlist.
  #
  # @return [void]
  def validate_content_type
    return if ALLOWED_CONTENT_TYPES.include?(file.content_type)

    errors.add(:file, "has an unsupported content type")
  end

  # Verifies that the file's magic bytes match its declared content type.
  #
  # @return [void]
  def validate_magic_bytes
    signatures = MAGIC_BYTES[file.content_type]
    return unless signatures

    file_header = read_file_header
    return if file_header.nil?

    matched = signatures.any? { |sig| file_header.start_with?(sig) }
    return if matched

    errors.add(:file, "content does not match its declared type")
  end

  # Validates that the file does not exceed the maximum size limit.
  #
  # @return [void]
  def validate_file_size
    return unless file.blob.byte_size > MAX_FILE_SIZE

    errors.add(:file, "is too large (maximum is 100 MB)")
  end

  # Reads the first 16 bytes of the attached file for magic byte verification.
  # Handles both persisted blobs (via service download) and non-persisted
  # blobs (via direct IO access on the attachment change).
  #
  # @return [String, nil] the file header bytes, or nil if unreadable
  def read_file_header
    if file.blob.persisted?
      file.blob.open { |tempfile| tempfile.read(16) }
    else
      read_header_from_attachment_change
    end
  rescue StandardError
    nil
  end

  # Reads header bytes from the pending attachment change IO.
  #
  # @return [String, nil] the file header bytes, or nil if unavailable
  def read_header_from_attachment_change
    change = attachment_changes["file"]
    return nil unless change

    attachable = change.attachable
    return nil unless attachable.is_a?(Hash) && attachable[:io].respond_to?(:read)

    io = attachable[:io]
    original_pos = io.pos
    io.rewind
    header = io.read(16)
    io.seek(original_pos)
    header
  end
end
