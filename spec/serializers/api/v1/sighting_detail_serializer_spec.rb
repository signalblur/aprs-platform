# frozen_string_literal: true

require "rails_helper"

RSpec.describe Api::V1::SightingDetailSerializer do
  subject(:json) { described_class.new(sighting, current_user: current_user).as_json }

  let(:current_user) { create(:user) }
  let(:shape) { create(:shape) }
  let(:sighting) { create(:sighting, submitter: current_user, shape: shape) }

  it "includes core sighting fields from SightingSerializer" do
    expect(json[:id]).to eq(sighting.id)
    expect(json[:description]).to eq(sighting.description)
    expect(json[:status]).to eq(sighting.status)
  end

  describe "physiological_effects" do
    it "returns empty array when none exist" do
      expect(json[:physiological_effects]).to eq([])
    end

    it "serializes physiological effect core fields" do
      effect = create(:physiological_effect, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      expect(result[:physiological_effects].length).to eq(1)
      expect(result[:physiological_effects].first[:id]).to eq(effect.id)
      expect(result[:physiological_effects].first[:effect_type]).to eq(effect.effect_type)
    end

    it "serializes physiological effect detail fields" do
      effect = create(:physiological_effect, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      expect(result[:physiological_effects].first[:severity]).to eq(effect.severity)
      expect(result[:physiological_effects].first[:onset]).to eq(effect.onset)
      expect(result[:physiological_effects].first[:duration]).to eq(effect.duration)
    end
  end

  describe "psychological_effects" do
    it "returns empty array when none exist" do
      expect(json[:psychological_effects]).to eq([])
    end

    it "serializes psychological effects" do
      effect = create(:psychological_effect, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      expect(result[:psychological_effects].length).to eq(1)
      expect(result[:psychological_effects].first[:id]).to eq(effect.id)
      expect(result[:psychological_effects].first[:effect_type]).to eq(effect.effect_type)
    end
  end

  describe "equipment_effects" do
    it "returns empty array when none exist" do
      expect(json[:equipment_effects]).to eq([])
    end

    it "serializes equipment effects" do
      effect = create(:equipment_effect, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      expect(result[:equipment_effects].length).to eq(1)
      expect(result[:equipment_effects].first[:id]).to eq(effect.id)
      expect(result[:equipment_effects].first[:equipment_type]).to eq(effect.equipment_type)
      expect(result[:equipment_effects].first[:effect_type]).to eq(effect.effect_type)
    end
  end

  describe "environmental_traces" do
    it "returns empty array when none exist" do
      expect(json[:environmental_traces]).to eq([])
    end

    it "serializes environmental traces" do
      trace = create(:environmental_trace, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      expect(result[:environmental_traces].length).to eq(1)
      expect(result[:environmental_traces].first[:id]).to eq(trace.id)
      expect(result[:environmental_traces].first[:trace_type]).to eq(trace.trace_type)
    end

    it "includes location hash for traces with location" do
      trace = create(:environmental_trace, :with_location, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      trace_json = result[:environmental_traces].first
      expect(trace_json[:location]).to eq({
        lat: trace.location.latitude,
        lng: trace.location.longitude
      })
    end

    it "returns nil location for traces without location" do
      create(:environmental_trace, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      expect(result[:environmental_traces].first[:location]).to be_nil
    end

    it "includes measurement fields" do
      trace = create(:environmental_trace, :with_measurement, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      trace_json = result[:environmental_traces].first
      expect(trace_json[:measured_value]).to eq(trace.measured_value)
      expect(trace_json[:measurement_unit]).to eq(trace.measurement_unit)
    end
  end

  describe "evidences" do
    it "returns empty array when none exist" do
      expect(json[:evidences]).to eq([])
    end

    it "serializes evidences" do
      evidence = create(:evidence, sighting: sighting, submitted_by: current_user)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      expect(result[:evidences].length).to eq(1)
      expect(result[:evidences].first[:id]).to eq(evidence.id)
      expect(result[:evidences].first[:evidence_type]).to eq(evidence.evidence_type)
      expect(result[:evidences].first[:created_at]).to eq(evidence.created_at.iso8601)
    end
  end

  describe "witnesses" do
    let!(:witness) { create(:witness, :with_statement, sighting: sighting) }

    context "when current_user is a member" do
      let(:current_user) { create(:user) }

      it "serializes witness without contact_info" do
        result = described_class.new(sighting.reload, current_user: current_user).as_json
        witness_json = result[:witnesses].first
        expect(witness_json[:id]).to eq(witness.id)
        expect(witness_json[:name]).to eq(witness.name)
        expect(witness_json[:statement]).to eq(witness.statement)
        expect(witness_json).not_to have_key(:contact_info)
      end
    end

    context "when current_user is an investigator" do
      let(:current_user) { create(:user, :investigator) }

      it "includes contact_info" do
        result = described_class.new(sighting.reload, current_user: current_user).as_json
        witness_json = result[:witnesses].first
        expect(witness_json[:contact_info]).to eq(witness.contact_info)
      end
    end

    context "when current_user is an admin" do
      let(:current_user) { create(:user, :admin) }

      it "includes contact_info" do
        result = described_class.new(sighting.reload, current_user: current_user).as_json
        witness_json = result[:witnesses].first
        expect(witness_json[:contact_info]).to eq(witness.contact_info)
      end
    end

    context "when witness is anonymous" do
      let!(:witness) { create(:witness, :anonymous, sighting: sighting) }

      it "returns nil for name" do
        result = described_class.new(sighting.reload, current_user: current_user).as_json
        expect(result[:witnesses].first[:name]).to be_nil
      end
    end

    it "includes credibility_notes" do
      noted_witness = create(:witness, :with_credibility_notes, sighting: sighting)
      result = described_class.new(sighting.reload, current_user: current_user).as_json
      witness_json = result[:witnesses].find { |w| w[:id] == noted_witness.id }
      expect(witness_json[:credibility_notes]).to eq(noted_witness.credibility_notes)
    end
  end
end
