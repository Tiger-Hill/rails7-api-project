class CreateDisplayData < ActiveRecord::Migration[7.0]
  def change
    create_table :display_data do |t|
      t.references :data_point, null: false, foreign_key: true
      t.references :table_column, null: false, foreign_key: true
      t.references :table_row, null: false, foreign_key: true
      t.string :value

      t.timestamps
    end
  end
end
