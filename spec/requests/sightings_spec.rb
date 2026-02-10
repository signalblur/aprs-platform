# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Sightings" do
  let(:user) { create(:user) }
  let(:shape) { create(:shape) }

  describe "GET /sightings" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        get sightings_path

        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated" do
      before { sign_in user }

      it "returns success" do
        get sightings_path

        expect(response).to have_http_status(:ok)
      end

      it "renders sighting data" do
        sighting = create(:sighting, shape: shape)

        get sightings_path

        expect(response.body).to include(shape.name)
        expect(response.body).to include(sighting.description.truncate(150))
      end

      it "orders sightings by most recent first" do
        old = create(:sighting, shape: shape, observed_at: 5.days.ago)
        recent = create(:sighting, shape: shape, observed_at: 1.hour.ago)

        get sightings_path

        body = response.body
        expect(body.index(recent.description.truncate(150))).to be < body.index(old.description.truncate(150))
      end

      it "paginates results at 20 per page" do
        create_list(:sighting, 21, shape: shape)

        get sightings_path

        expect(response.body).to include("pagy")
      end

      it "supports page param" do
        create_list(:sighting, 21, shape: shape)

        get sightings_path, params: { page: 2 }

        expect(response).to have_http_status(:ok)
      end

      it "includes GeoJSON data for the map" do
        create(:sighting, shape: shape, location: "POINT(-104.9903 39.7392)")

        get sightings_path

        expect(response.body).to include("FeatureCollection")
      end
    end

    context "with filters" do
      before { sign_in user }

      it "filters by status" do
        submitted = create(:sighting, shape: shape)
        create(:sighting, :verified, shape: shape)

        get sightings_path, params: { status: "submitted" }

        expect(response.body).to include(submitted.description.truncate(150))
      end

      it "filters by shape_id" do
        other_shape = create(:shape)
        matching = create(:sighting, shape: shape)
        create(:sighting, shape: other_shape)

        get sightings_path, params: { shape_id: shape.id }

        expect(response.body).to include(matching.description.truncate(150))
      end

      it "filters by date range" do
        recent = create(:sighting, shape: shape, observed_at: 2.days.ago)
        create(:sighting, shape: shape, observed_at: 30.days.ago)

        get sightings_path, params: { date_from: 7.days.ago.to_date.to_s, date_to: Date.current.to_s }

        expect(response.body).to include(recent.description.truncate(150))
      end

      it "filters by location radius" do
        create(:sighting, shape: shape, location: "POINT(-104.9903 39.7392)")
        create(:sighting, :in_nyc, shape: shape)

        get sightings_path, params: { lat: "39.7392", lng: "-104.9903", radius: "50000" }

        expect(response).to have_http_status(:ok)
      end

      it "filters by text search" do
        matching = create(:sighting, shape: shape, description: "Bright glowing orb hovered silently overhead")
        create(:sighting, shape: shape, description: "A loud rumbling noise came from the ground below")

        get sightings_path, params: { q: "glowing orb" }

        expect(response.body).to include(matching.description.truncate(150))
      end

      it "handles combined filters" do
        matching = create(:sighting, shape: shape, description: "Bright orb sighting in the sky above town",
                                     observed_at: 2.days.ago)
        create(:sighting, :verified, shape: shape, description: "Dark triangle flew silently overhead at night",
                                     observed_at: 2.days.ago)

        get sightings_path, params: { status: "submitted", q: "orb" }

        expect(response.body).to include(matching.description.truncate(150))
      end

      it "ignores blank filter params" do
        create(:sighting, shape: shape)

        get sightings_path, params: { status: "", shape_id: "", q: "" }

        expect(response).to have_http_status(:ok)
      end
    end
  end

  describe "GET /sightings/:id" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        sighting = create(:sighting, shape: shape)

        get sighting_path(sighting)

        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated" do
      before { sign_in user }

      it "returns success" do
        sighting = create(:sighting, shape: shape)

        get sighting_path(sighting)

        expect(response).to have_http_status(:ok)
      end

      it "renders sighting fields" do
        sighting = create(:sighting, shape: shape, description: "Bright diamond-shaped craft hovering silently")

        get sighting_path(sighting)

        expect(response.body).to include(sighting.description)
        expect(response.body).to include(shape.name)
      end

      it "renders associated physiological effects" do
        sighting = create(:sighting, shape: shape)
        create(:physiological_effect, sighting: sighting, effect_type: "headache")

        get sighting_path(sighting)

        expect(response.body).to include("headache")
      end

      it "renders associated psychological effects" do
        sighting = create(:sighting, shape: shape)
        create(:psychological_effect, sighting: sighting, effect_type: "time_loss")

        get sighting_path(sighting)

        expect(response.body).to include("time_loss")
      end

      it "renders associated equipment effects" do
        sighting = create(:sighting, shape: shape)
        create(:equipment_effect, sighting: sighting, equipment_type: "car_engine", effect_type: "shutdown")

        get sighting_path(sighting)

        expect(response.body).to include("car_engine")
      end

      it "renders associated environmental traces" do
        sighting = create(:sighting, shape: shape)
        create(:environmental_trace, sighting: sighting, trace_type: "ground_marking")

        get sighting_path(sighting)

        expect(response.body).to include("ground_marking")
      end

      it "renders associated evidence" do
        sighting = create(:sighting, shape: shape)
        create(:evidence, sighting: sighting, evidence_type: :photo, description: "Photo from phone")

        get sighting_path(sighting)

        expect(response.body).to include("Photo from phone")
      end

      it "renders associated witnesses" do
        sighting = create(:sighting, shape: shape)
        create(:witness, sighting: sighting, name: "John Doe", statement: "I saw the craft")

        get sighting_path(sighting)

        expect(response.body).to include("John Doe")
        expect(response.body).to include("I saw the craft")
      end

      it "hides contact_info from members" do
        sighting = create(:sighting, shape: shape)
        create(:witness, sighting: sighting, name: "Jane Doe", contact_info: "secret@example.com")

        get sighting_path(sighting)

        expect(response.body).not_to include("secret@example.com")
      end

      it "shows contact_info to investigators" do
        investigator = create(:user, :investigator)
        sign_in investigator

        sighting = create(:sighting, shape: shape)
        create(:witness, sighting: sighting, name: "Jane Doe", contact_info: "visible@example.com")

        get sighting_path(sighting)

        expect(response.body).to include("visible@example.com")
      end

      it "returns 404 for non-existent sighting" do
        get sighting_path(id: 999_999)

        expect(response).to have_http_status(:not_found)
      end

      it "renders GeoJSON for the map" do
        sighting = create(:sighting, shape: shape, location: "POINT(-104.9903 39.7392)")

        get sighting_path(sighting)

        expect(response.body).to include("FeatureCollection")
      end
    end
  end
end
