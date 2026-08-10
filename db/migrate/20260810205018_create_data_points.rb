class CreateDataPoints < ActiveRecord::Migration[7.0]
  def change
    create_table :data_points do |t|
      t.references :row, null: false, foreign_key: true
      t.references :column, null: false, foreign_key: true
      t.string :raw_value
      t.string :type

      t.timestamps
    end
  end
end
