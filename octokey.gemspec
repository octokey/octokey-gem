Gem::Specification.new do |s|
  s.name          = 'octokey'
  s.version       = '0.1.pre.2'
  s.summary       = 'Public key authentication for the web!'
  s.description   = 'Allows you to use secure authentication mechanisms in plcae of passwords'
  s.homepage      = 'https://github.com/octokey/octokey-gem'
  s.email         = 'conrad.irwin@gmail.com'
  s.authors       = ['Conrad Irwin']
  s.files         = Dir["lib/**/*.rb"]
  s.require_paths = ["lib"]

  s.add_development_dependency 'rspec'
  s.add_development_dependency 'active_support'
  s.add_development_dependency 'i18n'
  s.add_development_dependency 'simplecov'
end
