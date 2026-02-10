# frozen_string_literal: true

# Observer record linked to a UAP sighting report.
#
# Stores witness identity and statement information. Contact information
# is encrypted at rest via Active Record Encryption to protect PII.
# Witnesses can be anonymous (nil name and contact_info).
#
# @attr [Sighting] sighting the parent sighting report
# @attr [String, nil] name the witness's name (nil for anonymous)
# @attr [String, nil] contact_info encrypted contact details (email/phone)
# @attr [String, nil] statement the witness's account of the sighting
# @attr [String, nil] credibility_notes investigator notes on witness credibility
class Witness < ApplicationRecord
  belongs_to :sighting

  encrypts :contact_info
end
