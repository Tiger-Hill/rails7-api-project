class AddSlugToTableRow < ActiveRecord::Migration[7.0]
  def change
    add_column :table_rows, :slug, :string
    add_index :table_rows, :slug, unique: true
  end
end
