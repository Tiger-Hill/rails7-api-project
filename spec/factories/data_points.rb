FactoryBot.define do
  factory :data_point do
    row { nil }
    column { nil }
    raw_value { "MyString" }
    type { "" }
  end
end
