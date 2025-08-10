class Users::SessionsController < Devise::SessionsController
  respond_to :json

  def create
    self.resource = warden.authenticate!(auth_options)
    sign_in(resource_name, resource)
    yield resource if block_given?

    options = {}
    options[:meta] = { message: 'Successfully logged in.' }
    json_hash = UserSerializer.new(resource, options).serializable_hash

    render json: json_hash, status: 200
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
    options = {}
    options[:meta] = { message: 'You have been logged out.' }
    json_hash = UserSerializer.new(nil, options).serializable_hash

    render json: json_hash, status: 200
  end

  def log_out_failure
    options = {}
    options[:meta] = { error_message: 'Log out failed.' }
    json_hash = UserSerializer.new(nil, options).serializable_hash

    render json: json_hash, status: 422
  end
end
