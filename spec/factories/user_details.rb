FactoryBot.define do
  factory :user_detail do
  end

  trait :user_detail_1 do
    email { "u1@user.com"}
    title { "Mr"}
    first_name { "Jack"}
    last_name { "Sparrow" }
  end

  trait :user_detail_2 do
    email { "u1@user.com"}
    title { "Mr"}
    first_name { "Jamal"}
    last_name { "Jardin" }
  end
end
