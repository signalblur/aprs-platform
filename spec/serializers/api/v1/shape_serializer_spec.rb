# frozen_string_literal: true

require "rails_helper"

RSpec.describe Api::V1::ShapeSerializer do
  subject(:json) { described_class.new(shape).as_json }

  let(:shape) { create(:shape) }

  it "includes id" do
    expect(json[:id]).to eq(shape.id)
  end

  it "includes name" do
    expect(json[:name]).to eq(shape.name)
  end

  it "includes description" do
    expect(json[:description]).to eq(shape.description)
  end

  it "returns nil description when absent" do
    shape_without = create(:shape, :without_description)
    result = described_class.new(shape_without).as_json
    expect(result[:description]).to be_nil
  end

  it "returns exactly three keys" do
    expect(json.keys).to contain_exactly(:id, :name, :description)
  end
end
