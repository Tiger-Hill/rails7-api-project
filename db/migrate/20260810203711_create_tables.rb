class CreateTables < ActiveRecord::Migration[7.0]
  def change
    create_table :tables do |t|
      t.references :filing, null: false, foreign_key: true
      t.string :table_name

      t.timestamps
    end
  end
end
