class AddSlugToFilings < ActiveRecord::Migration[7.0]
  def change
    add_column :filings, :slug, :string
    add_index :filings, :slug, unique: true
  end
end
