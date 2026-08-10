class AddSlugToDisplaytables < ActiveRecord::Migration[7.0]
  def change
    add_column :displaytables, :slug, :string
    add_index :displaytables, :slug, unique: true
  end
end
