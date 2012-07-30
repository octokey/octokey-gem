if RUBY_VERSION =~ /1.9.3/ && RUBY_ENGINE == "ruby"
  require 'simplecov'
  SimpleCov.start
end

require './lib/octokey'
require 'active_support/core_ext'
Octokey::Config.hmac_secret = "12345"
Octokey::Config.valid_hostnames = ["example.com", "*.example.org"]
Octokey::Config.public_keys do |username, opts|
  opts[:public_keys]
end
