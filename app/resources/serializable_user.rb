class SerializableUser < JSONAPI::Serializable::Resource
  type 'users'

  id { @object.slug }

  has_one :user_detail

  attributes :slug, :email

end
