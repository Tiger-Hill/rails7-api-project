class UserDetailSerializer
  include JSONAPI::Serializer

  belongs_to :user
  set_id :slug

  attributes :email, :title, :first_name, :last_name
end
