require 'rails_helper'

RSpec.describe UserDetail, type: :model do
  before :each do
  end

  describe "# Global validations" do
    it "should be valid for user_1" do
      @valid_user = create(:user, :user_1)
      @valid_user_detail = create(
        :user_detail,
        :user_detail_1,
        user: @valid_user,
        email: @valid_user.email,
      )
      expect(@valid_user.valid?).to be true
      expect(@valid_user_detail.valid?).to be true
    end
  end
end
