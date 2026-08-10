class CreateDisplayTables < ActiveRecord::Migration[7.0]
  def change
    create_table :display_tables do |t|
      t.references :user, null: false, foreign_key: true
      t.references :company, null: false, foreign_key: true
      t.string :table_name

      t.timestamps
    end
  end
end
