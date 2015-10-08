source 'https://rubygems.org'

# Specify gem's dependencies in gemspec
gemspec

gem 'rspec-rails', group: [:development, :test]
group :test do
  gem 'rspec'
  gem 'fakeweb'
end

gem 'ambisafe', :git => 'https://bitbucket.org/ambisafe/client-ruby.git'
gem 'ffi' # required when doing Bitcoin.open_key in Ambisafe client