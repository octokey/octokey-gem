require './lib/octokey.rb'

# For packaging Octokey, please use "rake gems; rake pushgems".
# This gemspec will only generate the correct gem for the current platform.
$octokey_gem = Gem::Specification.new do |s|

  s.name          = 'octokey'
  s.version       = Octokey::VERSION
  s.summary       = 'Public key authentication for the web!'
  s.description   = 'Allows you to use secure authentication mechanisms in place of passwords'
  s.homepage      = 'https://github.com/octokey/octokey-gem'
  s.email         = ['conrad.irwin@gmail.com', 'martin@kleppmann.de']
  s.authors       = ['Conrad Irwin', 'Martin Kleppmann']
  s.files         = Dir["lib/**/*.rb"]
  s.require_paths = ["lib"]

  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'active_support'
  s.add_development_dependency 'i18n'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'yard'

  platform = $octokey_platform || RUBY_PLATFORM

  if platform == 'java'
    s.platform = platform
    s.add_dependency 'jruby-openssl'
  end
end
