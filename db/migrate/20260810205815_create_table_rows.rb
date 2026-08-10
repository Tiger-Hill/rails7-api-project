class CreateTableRows < ActiveRecord::Migration[7.0]
  def change
    create_table :table_rows do |t|
      t.references :display_table, null: false, foreign_key: true
      t.string :label
      t.references :row, null: false, foreign_key: true

      t.timestamps
    end
  end
end
