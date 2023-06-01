# *** registrations_controller.rb ***

class Users::RegistrationsController < Devise::RegistrationsController
  include RackSessionFix
  prepend_before_action :require_no_authentication, only: [:new, :create, :cancel]
  prepend_before_action :authenticate_scope!, only: [:edit, :update, :destroy]
  prepend_before_action :set_minimum_password_length, only: [:new, :edit]

  def create
    build_resource(sign_up_params)
    user_detail = UserDetail.new(user_detail_params)
    user_detail.email = resource.email
    user_detail.user = resource

    if resource.valid? && user_detail.valid?
      resource.save
      user_detail.save
    end

    yield resource if block_given?
    if resource.persisted?
      if resource.active_for_authentication?
        sign_up(resource_name, resource)
      else
        expire_data_after_sign_in!
      end
      render jsonapi: resource,
        include: [ :user_detail ],
        fields: { user_details: [:slug] },
        meta: { message: "Successfully signed up." },
        status: :ok
    else
      # clean_up_passwords resource
      set_minimum_password_length
      if !resource.valid? && !user_detail.valid?
        message = "User couldn't be created. #{resource.errors.full_messages.to_sentence} #{user_detail.errors.full_messages.to_sentence} "
      elsif !resource.valid?
        message = "User couldn't be created. #{resource.errors.full_messages.to_sentence}"
      else
        message = "User couldn't be created. #{user_detail.errors.full_messages.to_sentence}"
      end
      render jsonapi_errors: resource.errors,
        meta: { message: message },
        status: 422
    end
  end

  def update
    self.resource = resource_class.to_adapter.get!(send(:"current_#{resource_name}").to_key)
    resource_updated = update_resource(resource, account_update_params)
    render jsonapi: resource,
      include: [ :user_detail ],
      fields: { user_details: [:slug] },
      meta: { message: "Successfully updated details." },
      status: :ok
  end

  def destroy
    render jsonapi_errors: [],
      meta: { message: "Please contact tech support to delete your account." },
      status: 422
  end

  def cancel
    expire_data_after_sign_in!
    # redirect_to new_registration_path(resource_name)
  end

  protected

  def user_detail_params
    params.require(:user_detail).permit(:title, :first_name, :last_name)
  end

  def account_update_params
    devise_parameter_sanitizer.sanitize(:account_update)
  end

  private

end
