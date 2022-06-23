$LOAD_PATH.uniq!

require "rubygems"
require "signet"
require "rspec"
require "faraday"

SimpleCov.start if ENV["COVERAGE"]
