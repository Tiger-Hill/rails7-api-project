class CreateUserDetails < ActiveRecord::Migration[7.0]
  def change
    create_table :user_details do |t|
      t.references :user, null: false, foreign_key: true
      t.string :email
      t.string :title
      t.string :first_name
      t.string :last_name

      t.timestamps
    end
  end
end
