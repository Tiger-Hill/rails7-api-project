class Company < ApplicationRecord
  extend FriendlyId
  friendly_id :uuid, use: [:slugged, :finders]


end
