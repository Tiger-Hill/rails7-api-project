class UserSerializer
  include JSONAPI::Serializer

  set_id :uuid

  attributes :email

  has_one :user_detail
end
