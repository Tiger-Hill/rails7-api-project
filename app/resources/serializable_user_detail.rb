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
