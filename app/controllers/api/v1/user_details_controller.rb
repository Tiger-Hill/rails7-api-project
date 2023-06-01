class Api::V1::UserDetailsController < ApplicationController
  before_action :set_user_detail, only: [ :show, :update ]

  def show
    authorize @user_detail

    render jsonapi: @user_detail,
      include: [ :documents ],
      status: :ok
  end

  def update
    authorize @user_detail

    if @user_detail.update(user_detail_params)
      render  jsonapi: @user_detail,
              meta: { message: "Successfully updated user details!" },
              status: :ok
    else
      render jsonapi_errors: @user_detail,
        meta: { message: "Failed to update user details (Reason: #{@user_detail.errors.messages})" },
        status: 409
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
