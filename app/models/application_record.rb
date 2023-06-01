class ApplicationRecord < ActiveRecord::Base
  primary_abstract_class

  def uuid
    SecureRandom.hex(6)
  end
end
