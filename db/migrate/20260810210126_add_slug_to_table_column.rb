class AddSlugToTableColumn < ActiveRecord::Migration[7.0]
  def change
    add_column :table_columns, :slug, :string
    add_index :table_columns, :slug, unique: true
  end
end
