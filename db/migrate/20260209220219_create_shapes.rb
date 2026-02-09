class CreateShapes < ActiveRecord::Migration[8.1]
  def change
    create_table :shapes do |t|
      t.string :name, null: false
      t.text :description

      t.timestamps
    end

    add_index :shapes, :name, unique: true
  end
end
