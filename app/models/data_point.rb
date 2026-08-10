class DataPoint < ApplicationRecord
  belongs_to :row
  belongs_to :column
end
