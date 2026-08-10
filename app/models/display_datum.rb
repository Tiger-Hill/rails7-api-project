class DisplayDatum < ApplicationRecord
  belongs_to :data_point
  belongs_to :table_column
  belongs_to :table_row
end
