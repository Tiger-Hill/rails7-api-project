class CreateColumns < ActiveRecord::Migration[7.0]
  def change
    create_table :columns do |t|
      t.references :sub_table, null: false, foreign_key: true
      t.string :label

      t.timestamps
    end
  end
end
