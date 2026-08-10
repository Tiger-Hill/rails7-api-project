class AddSlugToSubTables < ActiveRecord::Migration[7.0]
  def change
    add_column :sub_tables, :slug, :string
    add_index :sub_tables, :slug, unique: true
  end
end
