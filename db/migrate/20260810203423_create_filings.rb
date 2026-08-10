class CreateFilings < ActiveRecord::Migration[7.0]
  def change
    create_table :filings do |t|
      t.references :company, null: false, foreign_key: true
      t.string :title
      t.string :filing_type

      t.timestamps
    end
  end
end
