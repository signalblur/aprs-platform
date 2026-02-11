# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Sightings" do
  let(:user) { create(:user) }
  let(:admin) { create(:user, :admin) }
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

  describe "GET /sightings/new" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        get new_sighting_path
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated" do
      before { sign_in user }

      it "returns success" do
        get new_sighting_path
        expect(response).to have_http_status(:ok)
      end

      it "shows the submission form" do
        get new_sighting_path
        expect(response.body).to include("Report a Sighting")
      end
    end
  end

  describe "POST /sightings" do
    let(:valid_params) do
      {
        sighting: {
          shape_id: shape.id,
          description: "A bright triangular craft hovered silently over the field for several minutes",
          observed_at: 1.day.ago.iso8601,
          observed_timezone: "America/Denver",
          num_witnesses: 2,
          latitude: "39.7392",
          longitude: "-104.9903",
          duration_seconds: 300,
          altitude_feet: 5000,
          visibility_conditions: "Clear skies",
          weather_notes: "No wind",
          media_source: "Phone camera"
        }
      }
    end

    context "when unauthenticated" do
      it "redirects to sign in" do
        post sightings_path, params: valid_params
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated" do
      before { sign_in user }

      it "creates a sighting with valid params" do
        expect {
          post sightings_path, params: valid_params
        }.to change(Sighting, :count).by(1)
        expect(response).to redirect_to(sighting_path(Sighting.last))
      end

      it "sets the submitter to the current user" do
        post sightings_path, params: valid_params
        expect(Sighting.last.submitter).to eq(user)
      end

      it "sets status to submitted" do
        post sightings_path, params: valid_params
        expect(Sighting.last.status).to eq("submitted")
      end

      it "converts latitude and longitude to a PostGIS point" do
        post sightings_path, params: valid_params
        sighting = Sighting.last
        expect(sighting.location).to be_present
        expect(sighting.location.y).to be_within(0.001).of(39.7392)
        expect(sighting.location.x).to be_within(0.001).of(-104.9903)
      end

      it "creates sighting without location when lat/lng are blank" do
        params = valid_params.deep_dup
        params[:sighting][:latitude] = ""
        params[:sighting][:longitude] = ""
        post sightings_path, params: params
        expect(Sighting.last.location).to be_nil
      end

      it "renders new on invalid params" do
        post sightings_path, params: { sighting: { description: "short", observed_at: "" } }
        expect(response).to have_http_status(:unprocessable_content)
      end

      it "does not allow setting status on create" do
        params = valid_params.deep_dup
        params[:sighting][:status] = "verified"
        post sightings_path, params: params
        expect(Sighting.last.status).to eq("submitted")
      end
    end

    context "when tier limit is reached" do
      before do
        sign_in user
        5.times { create(:sighting, submitter: user) }
      end

      it "redirects with unauthorized" do
        post sightings_path, params: valid_params
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "GET /sightings/:id/edit" do
    context "when unauthenticated" do
      it "redirects to sign in" do
        sighting = create(:sighting, submitter: user)
        get edit_sighting_path(sighting)
        expect(response).to redirect_to(new_user_session_path)
      end
    end

    context "when authenticated as the submitter" do
      before { sign_in user }

      it "returns success" do
        sighting = create(:sighting, submitter: user)
        get edit_sighting_path(sighting)
        expect(response).to have_http_status(:ok)
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "returns success" do
        sighting = create(:sighting, submitter: user)
        get edit_sighting_path(sighting)
        expect(response).to have_http_status(:ok)
      end
    end

    context "when authenticated as another user" do
      it "redirects with unauthorized" do
        other = create(:user)
        sign_in other
        sighting = create(:sighting, submitter: user)
        get edit_sighting_path(sighting)
        expect(response).to redirect_to(root_path)
      end
    end
  end

  describe "PATCH /sightings/:id" do
    context "when authenticated as the submitter" do
      before { sign_in user }

      it "updates the sighting" do
        sighting = create(:sighting, submitter: user)
        patch sighting_path(sighting), params: {
          sighting: { description: "Updated description with enough characters to pass validation" }
        }
        expect(response).to redirect_to(sighting_path(sighting))
        expect(sighting.reload.description).to eq("Updated description with enough characters to pass validation")
      end

      it "does not allow submitter to change status" do
        sighting = create(:sighting, submitter: user)
        patch sighting_path(sighting), params: { sighting: { status: "verified" } }
        expect(sighting.reload.status).to eq("submitted")
      end

      it "updates location when latitude and longitude are provided" do
        sighting = create(:sighting, submitter: user)
        patch sighting_path(sighting), params: {
          sighting: { latitude: "40.0150", longitude: "-105.2705" }
        }
        sighting.reload
        expect(sighting.location.y).to be_within(0.001).of(40.0150)
        expect(sighting.location.x).to be_within(0.001).of(-105.2705)
      end

      it "renders edit on invalid params" do
        sighting = create(:sighting, submitter: user)
        patch sighting_path(sighting), params: { sighting: { description: "short" } }
        expect(response).to have_http_status(:unprocessable_content)
      end
    end

    context "when authenticated as admin" do
      before { sign_in admin }

      it "allows admin to change status" do
        sighting = create(:sighting, submitter: user)
        patch sighting_path(sighting), params: { sighting: { status: "verified" } }
        expect(sighting.reload.status).to eq("verified")
      end
    end

    context "when authenticated as another user" do
      it "redirects with unauthorized" do
        other = create(:user)
        sign_in other
        sighting = create(:sighting, submitter: user)
        patch sighting_path(sighting), params: {
          sighting: { description: "Unauthorized update attempt for this sighting" }
        }
        expect(response).to redirect_to(root_path)
      end
    end
  end
end
