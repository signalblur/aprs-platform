# frozen_string_literal: true

# Reference data model for UAP shape categories.
#
# Stores the 25 standard shape classifications that observers select
# when reporting sightings. Seeded at setup via db/seeds.rb.
#
# @attr [String] name the shape category name (unique, required)
# @attr [String] description optional description of the shape category
class Shape < ApplicationRecord
  has_many :sightings, dependent: :restrict_with_error

  validates :name, presence: true, uniqueness: true
end
