class CreateTableColumns < ActiveRecord::Migration[7.0]
  def change
    create_table :table_columns do |t|
      t.references :display_table, null: false, foreign_key: true
      t.date :period_end_date

      t.timestamps
    end
  end
end
