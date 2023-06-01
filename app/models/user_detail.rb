class UserDetail < ApplicationRecord
  extend FriendlyId
  friendly_id :uuid, use: [ :slugged, :finders ]
  validates :title, inclusion: { in: %w[Mr Ms] }
  belongs_to :user
end
