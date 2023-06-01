class Users::SessionsController < Devise::SessionsController
  respond_to :json

  def create
    self.resource = warden.authenticate!(auth_options)
    sign_in(resource_name, resource)
    yield resource if block_given?
    render jsonapi: resource,
      include: [ :user_detail ],
      meta: { message: "Successfully logged in!" },
      status: :ok
  end

  def destroy
    signed_out = (Devise.sign_out_all_scopes ? sign_out : sign_out(resource_name))
    yield if block_given?
    respond_to_on_destroy
  end

  protected

  private

  def respond_to_on_destroy
      log_out_success && return if current_user

      log_out_failure
    end

  def log_out_success
    render jsonapi: [],
      meta: { message: "You have been logged out." },
      status: 200
  end

  def log_out_failure
    render jsonapi_errors: [],
      meta: { message: "Log out failed." },
      status: 422
  end
end
