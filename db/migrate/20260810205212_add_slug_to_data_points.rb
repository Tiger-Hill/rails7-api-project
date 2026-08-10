class AddSlugToDataPoints < ActiveRecord::Migration[7.0]
  def change
    add_column :data_points, :slug, :string
    add_index :data_points, :slug, unique: true
  end
end
