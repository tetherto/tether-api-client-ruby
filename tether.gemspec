Gem::Specification.new do |s|
  s.name        = 'tether'
  s.version     = '0.2'
  s.date        = '2015-10-08'
  s.summary     = 'Tether API client library'
  s.description = s.summary
  s.authors     = ['Oleh Vasylenko']
  s.email       = 'oleh@tether.to'
  s.homepage    = 'https://bitbucket.org/tetherto/tether-api-client-ruby'
  s.files       = `git ls-files`.split($/)

  s.add_dependency 'httparty', '>=0.13.0'
  s.add_dependency 'hashie',  '~> 3.0'
end