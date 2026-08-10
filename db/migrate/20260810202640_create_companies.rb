class CreateCompanies < ActiveRecord::Migration[7.0]
  def change
    create_table :companies do |t|
      t.string :company_name
      t.string :reference_type
      t.string :reference_value

      t.timestamps
    end
  end
end
