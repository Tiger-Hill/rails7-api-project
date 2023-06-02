Pre-requisites: Rails 7.0.4.3, Ruby 3.2.1, current as of 2023/06/01

This is a pretty (borderline excessively) detailed guide to help you set up a fully rounded development environment for a Rails 7 app in API mode. This can be puzzled together within days for a non-novice dev, but I wanted to save you the pain from chasing down various error messages to efficiently get to a developer-friendly setup within a few hours. 

From my choice of ruby / rails versions over `rails-jsonapi` to `friendly_id`: I have made many choices that you are welcome to change or disregard. Please jump to the appendix at the end to see which gems I've selected with links to relevant documentation or the [repo](https://github.com/Tiger-Hill/rails7-api-project/) for the below. Special thanks to [focus-me34](https://github.com/Focus-me34) & [mwinterdata](https://github.com/mwinterdata) for helping me with this :)

## App setup

Set up a new Rails project without the default testing suite, with postgres, called `rails7-api-project`
```bash
rails new -T \
  --database postgresql \
  --api rails7-api-project
```

Change into the folder and initiate the repo. Choose settings as per your preferences
```bash
cd rails7-api-project
gh repo create --private --source=.
```

Make your first commit.
```bash
git add .
git commit -m "First commit"
git push origin main
```

## Setting up dotenv to store secrets

We use .env files to store secrets.

Add the below to the gemfile in the `:development, :test` block
```ruby
# *** Gemfile ***

gem "dotenv-rails"
```

```bash
bundle install
```

Create a .env file to store your app secrets
```bash
touch .env
```

Add this file to gitignore so it won't get shared on on GH with the world.
```bash
echo '.env*' >> .gitignore
```

Create a secret.
```bash
rails secret
```

`rails secret` will give you a random string like ‘12312313213’

Copy the string into the .env file

```ruby
# *** .env ***

DEVISE_JWT_SECRET_KEY = 12312313213
```

Commit your code to GH. Note that the .env file is in gitignore and won't be pushed (even in this example).
```bash
ga .
gcmsg "Set up dotenv"
g push origin main
```

## Setting up devise and devise-jwt

Add devise, devise-jwt, and jsonapi-rails to the gemfile. Because this is an api app, we will be using JWT for authentification. You can use a different jsonapi parser if you want.
```ruby
# *** Gemfile ***

gem 'devise'
gem 'devise-jwt'
gem 'jsonapi-rails'
```

Install devise
```bash
bundle install
rails g devise:install
rails g devise User
rails db:drop db:create db:migrate
```

Change the user model user.rb to this
```ruby
# *** user.rb ***

class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :jwt_authenticatable,
         jwt_revocation_strategy: JwtDenylist
end
```

Add this to the `application_controller.rb`
```ruby
# *** application_controller.rb ***

  before_action :authenticate_user!
```

Commit your code to GH.
```bash
ga .
gcmsg "Set up devise"
g push origin main
```

Create the jwt model file 
```bash
touch app/models/jwt_denylist.rb
```

The file should have the following content
```ruby
# *** jwt_denylist.rb ***

class JwtDenylist < ApplicationRecord
  include Devise::JWT::RevocationStrategies::Denylist

  self.table_name = 'jwt_denylist'
end
```

Generate a migration file
```bash
rails g migration CreateJwtDenylist
```

Change the migration file’s content to
```ruby
# *** [TTTTTTTTTTTTTTTTTT]_create_jwt_denylist.rb ***

class CreateJwtDenylist < ActiveRecord::Migration[7.0]
  def change
    create_table :jwt_denylist do |t|
      t.string :jti, null: false
      t.datetime :exp, null: false
    end
    add_index :jwt_denylist, :jti
  end
end
```

```bash
rails db:migrate
```


Add this to devise's setup block:
```ruby
# *** config/initializers/devise.rb ***

  config.jwt do |jwt|
    jwt.secret = ENV['DEVISE_JWT_SECRET_KEY']
    jwt.expiration_time = 1.day.to_i
  end
```

Commit your code to GH.
```bash
ga .
gcmsg "Set up devise-jwt"
g push origin main
```


Create the folder for the devise controllers
```bash
mkdir app/controllers/users
```

Create a sessions controller
```bash
touch app/controllers/users/sessions_controller.rb
```

Use this in the sessions controller. We will make the user_details bits usable later. If you want to test it out with `rails s`, you have to hash out the user_detail bits.
```ruby
# *** sessions_controller.rb ***

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
```

Create a registrations controller
```bash
touch app/controllers/users/registrations_controller.rb
```

Use this in the registrations controller
```ruby
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
```

Set up the routes by amending the default devise routes:
```ruby
# *** routes.rb ***

Rails.application.routes.draw do
  devise_for :users,
             controllers: {
                 sessions: 'users/sessions',
                 registrations: 'users/registrations'
             }
end
```

Add this `rack_session_fix.rb` in order to deal with a problematic devise imeplentation for Rails 7. I got this from [here](https://github.com/waiting-for-dev/devise-jwt/issues/235#issuecomment-1214414894).
```bash
touch app/controllers/concerns/rack_session_fix.rb
```

Add the following content
```ruby
# *** rack_session_fix.rb ***

module RackSessionFix
  extend ActiveSupport::Concern
  class FakeRackSession < Hash
    def enabled?
      false
    end
  end
  included do
    before_action :set_fake_rack_session_for_devise
    private
    def set_fake_rack_session_for_devise
      request.env['rack.session'] ||= FakeRackSession.new
    end
  end
end
```

Commit your code to GH.
```bash
ga .
gcmsg "Set up devise controllers"
g push origin main
```

## Setting up CORS

Unhash the rack-cors gem in the Gemfile
```ruby
# *** Gemfile ***

gem 'rack-cors'
```

```bash
bundle install
```

Go to cors.rb and unhash the file content so it roughly looks like the below
```ruby
# *** cors.rb ***

Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins "example.com"

    resource "*",
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head]
  end
end
```

Commit
```bash
ga .
gcmsg "Set up cors"
g push origin main
```

## Setting up friendly_id

We will use friendly_id to anonymize all db entries. It's [documentation](https://github.com/norman/friendly_id) is excellent and we will only cover the bare basics here.

Add the below to the Gemfile
```ruby
# *** Gemfile ***

gem 'friendly_id', '~> 5.4.0'
```

Install friendly_id
```bash
bundle
rails generate friendly_id 
```

To add a friendly_id slug to the User table
```bash
rails g migration AddSlugToUsers slug:uniq
rails db:migrate
```

Go to the User model and add the following
```ruby
# *** user.rb ***

  extend FriendlyId
  friendly_id :uuid, use: [ :slugged, :finders ]
```

Add the following to `application_record.rb`
```ruby
# *** application_record.rb ***

  def uuid
    SecureRandom.hex(6)
  end
```

Commit
```bash
ga .
gcmsg "Set up friendly_id"
g push origin main
```

## Setting up testing environment
Add the below to the Development section of the gemfile

Test
Add the following to :development, :test in the gemfile
```ruby
# *** Gemfile ***

  gem 'rspec-rails', '~> 5.1'
  gem 'simplecov', require: false
  gem 'factory_bot_rails', '~> 6.2'
  gem 'database_cleaner', '~> 2.0', '>= 2.0.1'
  gem 'jsonapi-rspec'
```

```bash
bundle
bundle exec rails g rspec:install
```

Bring out the filter from `spec_helper.rb`
```ruby
# *** spec_helper.rb ***

  config.filter_run_when_matching :focus
```

Add the following to top of the rails_helper.rb file
```ruby
# *** rails_helper.rb, from top ***

require 'simplecov'
SimpleCov.start 'rails' do
  add_filter '/bin/'
  add_filter '/db/'
  add_filter '/spec/'
  add_filter "app/jobs/application_job.rb"
  # add_filter "app/channels/application_cable/channel.rb"
  # add_filter "app/channels/application_cable/connection.rb"
  # add_filter "app/controllers/users/"

  enable_coverage :branch
  #  add_group "Models", "app/models"
  add_group "Policies", "app/policies"
end
```

After the require 'spec_helper', add the following
```ruby
# *** rails_helper.rb, after: 'require 'spec_helper' ***

require 'support/database_cleaner'
require 'support/api_helper'
require 'devise/jwt/test_helpers'
require 'jsonapi/rspec'
```

For db_cleaner, change the following to the `Rspec.configure` block:
```ruby
# *** rails_helper.rb, within: Rspec.configure ***

  config.use_transactional_fixtures = false
```

For Factorybot, add this to the Rspec.configure block: 
```ruby
# *** rails_helper.rb, within: Rspec.configure ***

  config.include JSONAPI::RSpec
  config.include FactoryBot::Syntax::Methods
  config.include Devise::Test::IntegrationHelpers
```

Create the config file for db_cleaner
```bash
mkdir spec/support
touch spec/support/database_cleaner.rb
```

The content is as follows
```ruby
# *** database_cleaner.rb ***

RSpec.configure do |config|
  config.before(:suite) do
    DatabaseCleaner.clean_with :truncation, except: %w(ar_internal_metadata)
  end

  config.before(:each) do
    DatabaseCleaner.strategy = :truncation
  end

  config.before(:each) do
    DatabaseCleaner.start
  end

  config.after(:each) do
    DatabaseCleaner.clean
  end
end
```

Create this api_helper in order to be able to quickly handle logins in tests. This is derived from [here](https://github.com/waiting-for-dev/devise-jwt/issues/99).

```bash
touch spec/support/api_helper.rb
```

```ruby
# *** api_helper.rb ***

module ApiHelper
  def authenticated_header(user, headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' })
    Devise::JWT::TestHelpers.auth_headers(headers, user)
  end
end
```

Commit
```bash
ga .
gcmsg "Set up testing gems"
g push origin main
```

## Generating the first testable model controller: user_details

We will add a user_detail migration, where we will store `email`, `title`, `first_name`, and `last_name`.
```bash
rails g model user_detail user:references email:string title:string first_name:string last_name:string
```

The point of doing the test setup first is that you see that rspec automatically generates the test-files, although we have to do some renaming and moving for greater convenience down the line.

Let's slug this one real quick.

To add a friendly_id slug to the UserDetail table
```bash
rails g migration AddSlugToUserDetails slug:uniq
rails db:migrate
```

Go to user_detail.rb and add the following, including a small validation.
``` ruby
# *** user_detail.rb ***

  extend FriendlyId
  friendly_id :uuid, use: [ :slugged, :finders ]
  validates :title, inclusion: { in: %w[Mr Ms] }
  belongs_to :user
```

And add this to `user.rb`
```ruby
# *** user.rb ***

  has_one :user_detail
```

Let's set up a controller.

```bash
rails generate controller user_details
```

Move the controller to the right directory and (for ease of reference), please add `_controller_` to the request (i.e. controller) test file
```bash
mkdir app/controllers/api/
mkdir app/controllers/api/v1
mv app/controllers/user_details_controller.rb app/controllers/api/v1/user_details_controller.rb
mv spec/requests/user_details_spec.rb spec/requests/user_details_controller_spec.rb
```

Put this into the controller
```ruby
# *** user_details_controller.rb ***

class Api::V1::UserDetailsController < ApplicationController
  before_action :set_user_detail, only: [ :show, :update ]

  def show
    # authorize @user_detail

    render jsonapi: @user_detail,
      include: [ :documents ],
      status: :ok
  end

  def update
    # authorize @user_detail
    
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
```

Add the routes
```ruby
# *** routes.rb ***

  namespace :api do
    namespace :v1 do
      resources :user_details, only: [ :show, :update ]
    end
  end
```

Now, let's add some resources so that `rails-jsonapi` knows what to do.

```bash
mkdir app/resources/
touch app/resources/serializable_user.rb
touch app/resources/serializable_user_detail.rb
```

Put the below into the file `serializable_user.rb`
```ruby
# *** serializable_user.rb ***

class SerializableUser < JSONAPI::Serializable::Resource
  type 'users'

  id { @object.slug }

  has_one :user_detail

  attributes :slug, :email

end
```

Put the below into the file `serializable_user_detail.rb`
```ruby
# *** serializable_user_detail.rb ***

class SerializableUserDetail < JSONAPI::Serializable::Resource
  type 'user_details'

  id { @object.slug }

  belongs_to :user

  attributes  :slug,
              :email,
              :title,
              :first_name,
              :last_name
end
```

Commit
```bash
ga .
gcmsg "Set up first controller - without pundit"
g push origin main
```

## Time to curl

Let's fire up our server with
```bash
rails s
```

Let's sign up our first user:
```bash
curl -XPOST -i -H "Content-Type:   application/json" -d '{ "user": { "email":   "u1@user.com ", "password": "111111" },   "user_detail": { "title": "Mr",   "first_name": "Jack", "last_name":   "Sparrow" } }' http://localhost:3000/users/
```

The response should look something like
```bash
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 0
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: strict-origin-when-cross-origin
Content-Type: application/vnd.api+json
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwic2NwIjoidXNlciIsImF1ZCI6bnVsbCwiaWF0IjoxNjg0NTE1NTQ2LCJleHAiOjE2ODQ2MDE5NDYsImp0aSI6Ijg1M2RmNWE0LTUwMTYtNDA3Ni05Y2E1LTYzMjE1MzRiZTU2MyJ9.KIw1ty5uUQtKsmte9oZW-e__idgDOhf90ZMjX2wGdtk
ETag: W/"1a63d5576b7300538148f51684e78fe4"
Cache-Control: max-age=0, private, must-revalidate
X-Request-Id: 544de0b1-79d0-4ab1-b910-6f2419ae186a
X-Runtime: 0.443025
Server-Timing: sql.active_record;dur=43.08, start_processing.action_controller;dur=0.20, render.jsonapi-rails;dur=4.04, process_action.action_controller;dur=320.00
vary: Accept, Origin
Transfer-Encoding: chunked

{"data":{"id":"8d343da8607b","type":"users","attributes":{"slug":"8d343da8607b","email":"u1@user.com"},"relationships":{"user_detail":{"data":{"type":"user_details","id":"97201e7cce8b"}}}},"included":[{"id":"97201e7cce8b","type":"user_details","attributes":{"slug":"97201e7cce8b"}}],"meta":{"message":"Successfully signed up!"},"jsonapi":{"version":"1.0"}}%
```

We will now sign in
```bash
curl -XPOST -i -H "Content-Type:   application/json" -d '{ "user": { "email":   "u1@user.com ", "password": "111111" } }'   http://localhost:3000/users/sign_in
```

The expected response looks like this
```bash
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 0
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: strict-origin-when-cross-origin
Content-Type: application/vnd.api+json
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwic2NwIjoidXNlciIsImF1ZCI6bnVsbCwiaWF0IjoxNjg0NTE1ODM5LCJleHAiOjE2ODQ2MDIyMzksImp0aSI6IjEyYzkxMWY4LWJlZDQtNDUxNi1hZDU3LTJjNzE2OWRhODc2YSJ9.b6QQBn4zJrG2lpI7wpYDg7I93XH22NHx52loy71I3L0
ETag: W/"9152c635c47f1378477f7bd3dc22c026"
Cache-Control: max-age=0, private, must-revalidate
X-Request-Id: 6420f099-18e4-4197-bc40-7eaf8f340637
X-Runtime: 0.302670
Server-Timing: start_processing.action_controller;dur=0.27, sql.active_record;dur=3.37, instantiation.active_record;dur=0.43, render.jsonapi-rails;dur=21.16, process_action.action_controller;dur=280.76
vary: Accept, Origin
Transfer-Encoding: chunked

{"data":{"id":"8d343da8607b","type":"users","attributes":{"slug":"8d343da8607b","email":"u1@user.com"},"relationships":{"user_detail":{"data":{"type":"user_details","id":"97201e7cce8b"}}}},"included":[{"id":"97201e7cce8b","type":"user_details","attributes":{"slug":"97201e7cce8b","email":"u1@user.com ","title":"Mr","first_name":"Jack","last_name":"Sparrow"},"relationships":{"user":{"meta":{"included":false}}}}],"meta":{"message":"Successfully logged in!"},"jsonapi":{"version":"1.0"}}%
```

Note down the response, because we need the slug `97201e7cce8b` (which is equivalent to the id) and bearer token `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwic2NwIjoidXNlciIsImF1ZCI6bnVsbCwiaWF0IjoxNjg0NTE1ODM5LCJleHAiOjE2ODQ2MDIyMzksImp0aSI6IjEyYzkxMWY4LWJlZDQtNDUxNi1hZDU3LTJjNzE2OWRhODc2YSJ9.b6QQBn4zJrG2lpI7wpYDg7I93XH22NHx52loy71I3L0`

We will use this user_detail slug and Bearer token to query the user's details. NOTE: BELOW IS THE STRUCTURE, IT WILL NOT WORK FOR YOU AS IS! 
```bash
curl -XGET -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwic2NwIjoidXNlciIsImF1ZCI6bnVsbCwiaWF0IjoxNjg0NTE1ODM5LCJleHAiOjE2ODQ2MDIyMzksImp0aSI6IjEyYzkxMWY4LWJlZDQtNDUxNi1hZDU3LTJjNzE2OWRhODc2YSJ9.b6QQBn4zJrG2lpI7wpYDg7I93XH22NHx52loy71I3L0" -H "Content-Type: application/json"  http://localhost:3000/api/v1/user_details/97201e7cce8b
```

The expected response should look like
```bash
{"data":{"id":"97201e7cce8b","type":"user_details","attributes":{"slug":"97201e7cce8b","email":"u1@user.com ","title":"Mr","first_name":"Jack","last_name":"Sparrow"},"relationships":{"user":{"meta":{"included":false}}}},"jsonapi":{"version":"1.0"}}%
```

You can parse the jsonapi object for greater legibility [here](http://json.parser.online.fr/)

We can also quickly change our first name
```bash
curl -XPATCH -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwic2NwIjoidXNlciIsImF1ZCI6bnVsbCwiaWF0IjoxNjg0NTE1ODM5LCJleHAiOjE2ODQ2MDIyMzksImp0aSI6IjEyYzkxMWY4LWJlZDQtNDUxNi1hZDU3LTJjNzE2OWRhODc2YSJ9.b6QQBn4zJrG2lpI7wpYDg7I93XH22NHx52loy71I3L0" -H "Content-Type: application/json" -d '{ "user_detail": { "first_name": "Jacqueline"} }' http://localhost:3000/api/v1/user_details/97201e7cce8b
```

For this kind of response:
```bash
{"data":{"id":"97201e7cce8b","type":"user_details","attributes":{"slug":"97201e7cce8b","email":"u1@user.com ","title":"Mr","first_name":"Jacqueline","last_name":"Sparrow"},"relationships":{"user":{"meta":{"included":false}}}},"meta":{"message":"Successfully updated user details!"},"jsonapi":{"version":"1.0"}}{"data":{"id":"97201e7cce8b","type":"user_details","attributes":{"slug":"97201e7cce8b","email":"u1@user.com ","title":"Mr","first_name":"Jacqueline","last_name":"Sparrow"},"relationships":{"user":{"meta":{"included":false}}}},"meta":{"message":"Successfully updated user details!"},"jsonapi":{"version":"1.0"}}%
```

Unfortunately, we can sign up a new user...
```bash
curl -XPOST -i -H "Content-Type:   application/json" -d '{ "user": { "email":   "u2@user.com ", "password": "111111" },   "user_detail": { "title": "Mr",   "first_name": "Jamal", "last_name":   "Jardin" } }' http://localhost:3000/users/
```

To get (without headers)
```bash
{"data":{"id":"b5b3fd575876","type":"users","attributes":{"slug":"b5b3fd575876","email":"u2@user.com"},"relationships":{"user_detail":{"data":{"type":"user_details","id":"eb2a7d38503a"}}}},"included":[{"id":"eb2a7d38503a","type":"user_details","attributes":{"slug":"eb2a7d38503a"}}],"meta":{"message":"Successfully signed up!"},"jsonapi":{"version":"1.0"}}%
```

But we can still rename him with u1's Bearer token. NOTE: we changed the id of the url
```bash
curl -XPATCH -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwic2NwIjoidXNlciIsImF1ZCI6bnVsbCwiaWF0IjoxNjg0NTE1ODM5LCJleHAiOjE2ODQ2MDIyMzksImp0aSI6IjEyYzkxMWY4LWJlZDQtNDUxNi1hZDU3LTJjNzE2OWRhODc2YSJ9.b6QQBn4zJrG2lpI7wpYDg7I93XH22NHx52loy71I3L0" -H "Content-Type: application/json" -d '{ "user_detail": { "first_name": "Jacqueline"} }' http://localhost:3000/api/v1/user_details/eb2a7d38503a
```

That's not good. Time for pundit!

## Adding pundit 
Add the following gem
```ruby
# *** Gemfile ***

gem 'pundit', '~> 2.3', git: 'https://github.com/varvet/pundit'
```
Note: the reason why we are fetching the latest pundit version from GH is because `exists?` was deprecated in Ruby 3.2 yet and Pundit 2.3.0 did not have this change incorporated yet.

Then run
```bash
bundle
rails g pundit:install
```

Add the below to the `application_controller.rb`
```ruby
# *** application_controller.rb ***

  include Pundit::Authorization

  # Pundit: allow-list approach
  after_action :verify_authorized, except: :index, unless: :skip_pundit?
  after_action :verify_policy_scoped, only: :index, unless: :skip_pundit?

  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized
  def user_not_authorized
    render jsonapi_errors: [],
      meta: { message: "You are not authorized to perform this action." },
      status: 403
  end

  private

  def skip_pundit?
    devise_controller? || params[:controller] =~ /(^(rails_)?admin)|(^pages$)/
  end
```

Let's generate a policy
```bash
rails generate pundit:policy user_detail
```

In the `user_details_controller.rb`, unhash the two lines within the #show and #update methods.
```ruby
# *** user_details_controller.rb ***

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
```

The `user_detail_policy.rb`, you change to
```ruby
# *** user_detail_policy.rb ***

class UserDetailPolicy < ApplicationPolicy
  class Scope < Scope
    # NOTE: Be explicit about which records you allow access to!
    # def resolve
    #   scope.all
    # end
  end

  def show?
    record.user == user
  end

  def update?
    show?
  end
end
```

If you have not already, restart the server with `Ctrl + c` and then again
```bash
rails s
```

Now, we should not be able to change u2's email with u1's credentials anymore
```bash
curl -XPATCH -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwic2NwIjoidXNlciIsImF1ZCI6bnVsbCwiaWF0IjoxNjg0NTE1ODM5LCJleHAiOjE2ODQ2MDIyMzksImp0aSI6IjEyYzkxMWY4LWJlZDQtNDUxNi1hZDU3LTJjNzE2OWRhODc2YSJ9.b6QQBn4zJrG2lpI7wpYDg7I93XH22NHx52loy71I3L0" -H "Content-Type: application/json" -d '{ "user_detail": { "first_name": "Jacqueline"} }' http://localhost:3000/api/v1/user_details/eb2a7d38503a
```

The expected response
```bash
{"meta":{"message":"You are not authorized to perform this action."},"jsonapi":{"version":"1.0"}}%
```

Voila. Time to commit.

```bash
ga .
gcmsg "Set up pundit"
g push origin main
```

## Writing some tests

We will first get going by setting up some factories
```bash
touch spec/factories/users.rb
```

Within `users.rb` we will replace the contents with the below
```ruby
# *** users.rb ***

FactoryBot.define do
  factory :user do
  end

  trait :user_1 do
    email { "u1@user.com"}
    password { "111111" }
  end

  trait :user_2 do
    email { "u2@user.com"}
    password { "111111" }
  end
end
```



Within `user_details.rb` we will replace the contents with the below
```ruby
# *** user_details.rb ***

FactoryBot.define do
  factory :user_detail do
  end

  trait :user_detail_1 do
    email { "u1@user.com"}
    title { "Mr"}
    first_name { "Jack"}
    last_name { "Sparrow" }
  end

  trait :user_detail_2 do
    email { "u1@user.com"}
    title { "Mr"}
    first_name { "Jamal"}
    last_name { "Jardin" }
  end
end
```

Rspec testing is a whole universe in itself, however, I just want to briefly demonstrate model testing and then on EE-style test where we tie everything together.

Go to the automatically generated `user_detail_spec.rb` and replace the content with the below:
```ruby
# *** user_detail_spec.rb ***

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
```

We will also hash out the contents of `user_detail_policy_spec.rb` because we won't be using this suite of tests

```ruby
# *** user_detail_policy_spec.rb *** 

require 'rails_helper'

RSpec.describe UserDetailPolicy, type: :policy do
  # let(:user) { User.new }

  # subject { described_class }

  # permissions ".scope" do
  #   pending "add some examples to (or delete) #{__FILE__}"
  # end

  # permissions :show? do
  #   pending "add some examples to (or delete) #{__FILE__}"
  # end

  # permissions :create? do
  #   pending "add some examples to (or delete) #{__FILE__}"
  # end

  # permissions :update? do
  #   pending "add some examples to (or delete) #{__FILE__}"
  # end

  # permissions :destroy? do
  #   pending "add some examples to (or delete) #{__FILE__}"
  # end
end
```

Afterwards, let's run
```bash
rspec spec
```

A few empty templates aside, the test is green. YAY.

I will demonstrate a controller test. Put the below in `user_details_controller_spec.rb`

```ruby
# *** user_details_controller_spec.rb ***

require 'rails_helper'
include ApiHelper

# RSpec.describe "UserDetails", type: :controller do
# describe RegistrationsController, type: :request do
RSpec.describe Api::V1::UserDetailsController, type: :request do
  before :each do
    @valid_user_1 = create(:user, :user_1)
    @valid_user_detail_1 = create( :user_detail, :user_detail_1, user: @valid_user_1, email: @valid_user_1.email )

    @valid_user_2 = create(:user, :user_2)
    @valid_user_detail_2 = create( :user_detail, :user_detail_2, user: @valid_user_2, email: @valid_user_2.email )
  end

  context "for an existing user" do
    it "allows sign-ins" do
      headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
      post "/users/sign_in", headers: headers, params: {
        user: {
          email: @valid_user_1.email,
          password: @valid_user_1.password
        }
      }.to_json
      puts response.body
      document = JSON.parse(response.body)
      expect(response.status).to eq(200)
    end

    it "does not allow sign-ins for users that don't exist" do
      headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
      post "/users/sign_in", headers: headers, params: {
        user: {
          email: "asdasda@gmail.com",
          password: '111111111111111111111111asdasdasdasd'
        }
      }.to_json

      puts response.body
      document = JSON.parse(response.body)
      # ! Note: the response works but doesn't conform to JSONAPI
      expect(response.status).to eq(401)
    end

    it "does not allow sign-ins with the wrong password" do
      headers = { 'Accept' => 'application/json', 'Content-Type' => 'application/json' }
      post "/users/sign_in", headers: headers, params: {
        user: {
          email: @valid_user_1.email,
          password: '111111111111111111111111asdasdasdasd'
        }
      }.to_json
      # p response
      puts response.body
      document = JSON.parse(response.body)
      # ! Note: the response works but doesn't conform to JSONAPI
      expect(response.status).to eq(401)
    end

    it "displays to get the user_details#show information" do
      get "/api/v1/user_details/#{@valid_user_detail_1.slug}", headers: authenticated_header(@valid_user_1)
      document = JSON.parse(response.body)
      expect(response.status).to eq(200)
      expect(document).to have_jsonapi_object
      expect(document['data']).to have_type('user_details')
    end

    it "updates the user's user_details - note that with the React frontend, we will realistically get an entire object back" do
      patch "/api/v1/user_details/#{@valid_user_detail_1.slug}", params: {
          user_detail: {
            first_name: "Jacqueline",
          },
        }.to_json,
        headers: authenticated_header(@valid_user_1)

      puts response.body
      document = JSON.parse(response.body)
      expect(response.status).to eq(200)
      expect(document).to have_jsonapi_object
      expect(document['data']).to have_type('user_details')
      expect(document['data']['attributes']['first_name']).to eq('Jacqueline')
    end

    it "throws an error if the user's user_details cannot be updated" do
      patch "/api/v1/user_details/#{@valid_user_detail_1.slug}", params: {
          user_detail: {
            title: "This is an invalid title",
          },
        }.to_json,
        headers: authenticated_header(@valid_user_1)

      puts response.body
      document = JSON.parse(response.body)
      expect(response.status).to eq(409)
      expect(document).to have_jsonapi_object
    end
  end
end
```

Run
```bash
rspec spec
```

And we got a sea of green. YAY. There's a lot going on that one can figure out using documentation but it's worth pointing out that `headers: authenticated_header(@valid_user_1)` takes advantage of our api_helper.rb to create authenticated headers for each http request, so that we do not need to manually extract the Bearer tokens. There are more details, e.g. why we had to append a `.to_json` at the end of the body of the request, however one need not and must not do so if one is attaching files, but that's someone else's problem now.

And if I still have not lost you, you can look at the beautiful test coverage of our app by running (on Linux at least)
```bash
xdg-open coverage/index.html
```

For the final commit
```bash
ga .
gcmsg "We're done"
g push origin main
```

## Appendix

`gem "dotenv-rails"`: to elegantly hide secrets. It's so simple, you probably don't need to read the [documentation](https://github.com/bkeepers/dotenv)

`gem 'devise'`: the sine qua non of rails authentification. Read more [here](https://github.com/heartcombo/devise/)

`gem 'devise-jwt'`: this allows you to use devise with jwt-tokens. Read more [here](https://github.com/waiting-for-dev/devise-jwt)

`gem 'jsonapi-rails'`: unfortunately not being worked on anymore, but it's a very fast and reasonably feature-rich and easy to use json-api renderer. Read more [here](https://jsonapi-rb.org/)

`gem 'friendly_id', '~> 5.4.0'`: easy to use gem with many more additional functions. Read more [here](https://github.com/norman/friendly_id)

`gem 'pundit', '~> 2.3', git: 'https://github.com/varvet/pundit'`: like `devise` but for authorization. Slightly temperamental but very powerful. Read more [here](https://github.com/varvet/pundit)

`gem 'rspec-rails', '~> 5.1'`: my preferred test suite. Read more [here](https://github.com/rspec/rspec-rails)

`gem 'simplecov'`: simple coverage generator that tells you how much and how well your code is covered by tests. Read more [here](https://github.com/simplecov-ruby/simplecov)

`gem 'factory_bot_rails', '~> 6.2'`: Allows you to efficiently and quickly create db entries. Read more [here](https://github.com/thoughtbot/factory_bot_rails)

`database_cleaner`: quickly resets your test db after each test. Read more [here](https://github.com/DatabaseCleaner/database_cleaner)

`gem 'jsonapi-rspec'`: provides some rspec matchers to somewhat efficiently parse jsonapi-compliant output in a test setting. Read more [here](https://github.com/jsonapi-rb/jsonapi-rspec)
