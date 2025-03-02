class UserDetailSerializer
  include JSONAPI::Serializer

  belongs_to :user

  attributes :email, :title, :first_name, :last_name
end
