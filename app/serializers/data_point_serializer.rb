class DataPointSerializer
  include JSONAPI::Serializer
  attributes :raw_value
end
