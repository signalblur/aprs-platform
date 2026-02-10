# frozen_string_literal: true

require "rails_helper"

RSpec.configure do |config|
  config.openapi_root = Rails.root.join("swagger").to_s

  config.openapi_specs = {
    "v1/swagger.yaml" => {
      openapi: "3.0.3",
      info: {
        title: "APRS API",
        version: "v1",
        description: "Anomalous Phenomena Reporting System — read-only API for UAP sighting data.",
        license: {
          name: "AGPL-3.0",
          url: "https://www.gnu.org/licenses/agpl-3.0.html"
        },
        contact: {
          name: "APRS on GitHub",
          url: "https://github.com/signalblur/aprs-platform"
        }
      },
      paths: {},
      servers: [
        { url: "{protocol}://{host}", variables: {
          protocol: { default: "https", enum: %w[https http] },
          host: { default: "localhost:3000" }
        } }
      ],
      components: {
        securitySchemes: {
          api_key: {
            type: :apiKey,
            name: "X-Api-Key",
            in: :header,
            description: "API key for authentication. Obtain via user account."
          }
        },
        schemas: {
          Location: {
            type: :object,
            nullable: true,
            properties: {
              lat: { type: :number, format: :double, description: "Latitude (WGS 84)" },
              lng: { type: :number, format: :double, description: "Longitude (WGS 84)" }
            },
            required: %w[lat lng]
          },
          PaginationMeta: {
            type: :object,
            properties: {
              page: { type: :integer, example: 1 },
              per_page: { type: :integer, example: 20 },
              total: { type: :integer, example: 42 },
              total_pages: { type: :integer, example: 3 }
            },
            required: %w[page per_page total total_pages]
          },
          ErrorResponse: {
            type: :object,
            properties: {
              error: { type: :string, example: "Unauthorized" }
            },
            required: %w[error]
          },
          Shape: {
            type: :object,
            properties: {
              id: { type: :integer },
              name: { type: :string, example: "Disc" },
              description: { type: :string, nullable: true, example: "Flat disc-shaped object" }
            },
            required: %w[id name]
          },
          ShapeReference: {
            type: :object,
            description: "Abbreviated shape (id + name only), embedded in sighting responses.",
            properties: {
              id: { type: :integer },
              name: { type: :string, example: "Triangle" }
            },
            required: %w[id name]
          },
          SightingSummary: {
            type: :object,
            properties: {
              id: { type: :integer },
              description: { type: :string },
              status: { type: :string, enum: %w[submitted under_review verified rejected] },
              shape: { "$ref": "#/components/schemas/ShapeReference" },
              location: { "$ref": "#/components/schemas/Location" },
              altitude_feet: { type: :number, format: :double, nullable: true },
              duration_seconds: { type: :integer, nullable: true },
              num_witnesses: { type: :integer },
              visibility_conditions: { type: :string, nullable: true },
              weather_notes: { type: :string, nullable: true },
              media_source: { type: :string, nullable: true },
              observed_at: { type: :string, format: "date-time" },
              observed_timezone: { type: :string, example: "America/Denver" },
              created_at: { type: :string, format: "date-time" },
              updated_at: { type: :string, format: "date-time" }
            },
            required: %w[id description status shape observed_at observed_timezone created_at updated_at]
          },
          PhysiologicalEffect: {
            type: :object,
            properties: {
              id: { type: :integer },
              effect_type: { type: :string },
              description: { type: :string, nullable: true },
              severity: { type: :string, enum: %w[mild moderate severe], nullable: true },
              onset: { type: :string, nullable: true },
              duration: { type: :string, nullable: true }
            },
            required: %w[id effect_type]
          },
          PsychologicalEffect: {
            type: :object,
            properties: {
              id: { type: :integer },
              effect_type: { type: :string },
              description: { type: :string, nullable: true },
              severity: { type: :string, enum: %w[mild moderate severe], nullable: true },
              onset: { type: :string, nullable: true },
              duration: { type: :string, nullable: true }
            },
            required: %w[id effect_type]
          },
          EquipmentEffect: {
            type: :object,
            properties: {
              id: { type: :integer },
              equipment_type: { type: :string },
              effect_type: { type: :string },
              description: { type: :string, nullable: true }
            },
            required: %w[id equipment_type effect_type]
          },
          EnvironmentalTrace: {
            type: :object,
            properties: {
              id: { type: :integer },
              trace_type: { type: :string },
              description: { type: :string, nullable: true },
              location: { "$ref": "#/components/schemas/Location" },
              measured_value: { type: :number, format: :double, nullable: true },
              measurement_unit: { type: :string, nullable: true }
            },
            required: %w[id trace_type]
          },
          Evidence: {
            type: :object,
            properties: {
              id: { type: :integer },
              evidence_type: { type: :string, enum: %w[photo video audio document other] },
              description: { type: :string, nullable: true },
              created_at: { type: :string, format: "date-time" }
            },
            required: %w[id evidence_type created_at]
          },
          Witness: {
            type: :object,
            description: "Witness record. The contact_info field is only included for " \
                         "users with investigator or admin role (PII gating).",
            properties: {
              id: { type: :integer },
              name: { type: :string, nullable: true },
              statement: { type: :string, nullable: true },
              credibility_notes: { type: :string, nullable: true },
              contact_info: {
                type: :string,
                nullable: true,
                description: "Only present for investigator/admin users."
              }
            },
            required: %w[id]
          },
          SightingDetail: {
            allOf: [
              { "$ref": "#/components/schemas/SightingSummary" },
              {
                type: :object,
                properties: {
                  physiological_effects: {
                    type: :array, items: { "$ref": "#/components/schemas/PhysiologicalEffect" }
                  },
                  psychological_effects: {
                    type: :array, items: { "$ref": "#/components/schemas/PsychologicalEffect" }
                  },
                  equipment_effects: {
                    type: :array, items: { "$ref": "#/components/schemas/EquipmentEffect" }
                  },
                  environmental_traces: {
                    type: :array, items: { "$ref": "#/components/schemas/EnvironmentalTrace" }
                  },
                  evidences: {
                    type: :array, items: { "$ref": "#/components/schemas/Evidence" }
                  },
                  witnesses: {
                    type: :array, items: { "$ref": "#/components/schemas/Witness" }
                  }
                },
                required: %w[physiological_effects psychological_effects equipment_effects
                             environmental_traces evidences witnesses]
              }
            ]
          }
        }
      }
    }
  }

  config.openapi_format = :yaml
end
