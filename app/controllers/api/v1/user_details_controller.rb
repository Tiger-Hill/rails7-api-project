class Api::V1::UserDetailsController < ApplicationController
  before_action :set_user_detail, only: [ :show, :update ]

  def show
    authorize @user_detail

    options = {}
    options[:meta] = { message: 'Successfully returned user detail.' }
    json_hash = UserDetailSerializer.new(@user_detail, options).serializable_hash

    render json: json_hash, status: 200
  end

  def update
    authorize @user_detail

    options = {}
    if @user_detail.update(user_detail_params)
      options[:meta] = { message: 'Successfully updated user detail.' }
      json_hash = UserDetailSerializer.new(@user_detail, options).serializable_hash

      render json: json_hash, status: 200
    else
      options[:meta] = { error_message: "Failed to update user details (Reason(s): #{@user_detail.errors.full_messages})." }
      json_hash = UserDetailSerializer.new(@user_detail, options).serializable_hash

      render json: json_hash, status: 409
    end
  end

  private

  def set_user_detail
    @user_detail = UserDetail.friendly.find_by_friendly_id(params[:id])
  end

  def user_detail_params
    params.require(:user_detail).permit(
      :title,
      :first_name,
      :last_name,
    )
  end
end
