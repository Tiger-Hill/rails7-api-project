class AddSlugToDisplayData < ActiveRecord::Migration[7.0]
  def change
    add_column :display_data, :slug, :string
    add_index :display_data, :slug, unique: true
  end
end
