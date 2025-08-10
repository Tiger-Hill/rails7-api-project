class UserSerializer
  include JSONAPI::Serializer

  set_id :slug

  attributes :email

  has_one :user_detail
end
