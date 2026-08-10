class AddSlugToRows < ActiveRecord::Migration[7.0]
  def change
    add_column :rows, :slug, :string
    add_index :rows, :slug, unique: true
  end
end
