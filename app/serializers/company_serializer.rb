class CompanySerializer
  include JSONAPI::Serializer
  attributes :company_name, :reference_type, :reference_value
end
