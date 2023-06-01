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
