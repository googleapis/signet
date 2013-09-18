require 'base64'
# Backport from ruby-1.9 to ruby-1.8
unless Base64.respond_to?(:strict_encode64)
  def Base64.strict_encode64(str)
    Base64.encode64(str).gsub("\n", "")
  end
end
