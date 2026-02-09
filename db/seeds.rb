# frozen_string_literal: true

# Seed UAP shape reference data.
#
# Uses find_or_create_by! for idempotency — safe to run multiple times.

shapes = [
  { name: "Sphere", description: "A round, ball-shaped object" },
  { name: "Orb", description: "A glowing or luminous spherical object" },
  { name: "Triangle", description: "A three-sided or triangular craft" },
  { name: "Boomerang/V-Shape", description: "A curved or V-shaped craft" },
  { name: "Chevron", description: "An angular V or chevron-shaped craft" },
  { name: "Diamond", description: "A diamond or rhombus-shaped object" },
  { name: "Disk/Saucer", description: "A flat, disk-like or classic flying saucer shape" },
  { name: "Oval/Egg", description: "An oval or egg-shaped object" },
  { name: "Cylinder/Cigar", description: "A long, cylindrical or cigar-shaped craft" },
  { name: "Rectangle", description: "A rectangular or box-shaped object" },
  { name: "Cross", description: "A cross or plus-sign-shaped object" },
  { name: "Star", description: "A star-shaped or multi-pointed object" },
  { name: "Cone", description: "A cone or conical-shaped object" },
  { name: "Teardrop", description: "A teardrop or pear-shaped object" },
  { name: "Fireball", description: "A bright, fiery object moving through the sky" },
  { name: "Light (single)", description: "A single unexplained point or area of light" },
  { name: "Light (multiple/formation)", description: "Multiple lights in a pattern or formation" },
  { name: "Flash/Strobe", description: "A brief flash or strobing light phenomenon" },
  { name: "Beam/Ray", description: "A directed beam or ray of light" },
  { name: "Cloud-like/Amorphous", description: "An amorphous, cloud-like, or hazy object" },
  { name: "Tic-Tac/Capsule", description: "An oblong capsule shape, like the well-known Tic-Tac description" },
  { name: "Dumbbell", description: "Two connected spheres or a dumbbell-shaped object" },
  { name: "Saturn-shape", description: "A sphere with a visible ring or band around it" },
  { name: "Morphing/Shape-shifting", description: "An object that appeared to change shape during observation" },
  { name: "Other/Unknown", description: "A shape not matching any standard category" }
]

shapes.each do |attrs|
  Shape.find_or_create_by!(name: attrs[:name]) do |shape|
    shape.description = attrs[:description]
  end
end

Rails.logger.info { "Seeded #{Shape.count} shapes" }
