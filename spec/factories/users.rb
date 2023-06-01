FactoryBot.define do
  factory :user do
  end

  trait :user_1 do
    email { "u1@user.com"}
    password { "111111" }
  end

  trait :user_2 do
    email { "u2@user.com"}
    password { "111111" }
  end
end
