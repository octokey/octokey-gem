This is the Ruby version of [Octokey](http://octokey.herokuapp.com/).

Installation
============

As with all rubygems you can just:
```bash
gem install octokey
```
Or, if you're using bundler, you can add the following to your `Gemfile`.
```ruby
source :rubygems
gem 'octokey'
```

Usage 
=====

In order for Octokey to work, you'll need the browser extension installed.

The first step to supporting Octokey on the server is to make an endpoint that generates challenges. For example, with sinatra:

```ruby
get '/octokey_challenge' do
  # TODO: make sure you're not returning the IP address of an HTTP proxy
  # like nginx here! You need the original IP address of the client.
  Octokey.new_challenge(:client_ip => request.env['CLIENT_IP'])
end
```

The second step is to handle requests for signup and login:

```ruby
get '/signup' do
  signup = Octokey.new(params['octokey_auth_request'],
                       :username => params['username'],
                       :client_ip => request.env['CLIENT_IP'])
  if signup.can_sign_up?
    # create the user!
    [200, {}, "200 OK"]
  elsif signup.should_retry?
    [310, {}, "310 Please request a new challenge"]
  else
    [400, {}, "400 Bad request"]
  end
end

get '/login' do
  login = Octokey.new(params['octokey_auth_request'],
                       :username => params['username'],
                       :client_ip => request.env['CLIENT_IP'])
  if login.can_log_in?
    # create the user!
    [200, {}, "200 OK"]
  elsif login.should_retry?
    [310, {}, "310 Please request a new challenge"]
  else
    [400, {}, "400 Bad request"]
  end
end
```


Configuration
=============

Configuring Octokey to run with your web-framework should be easy, feel free to copy the example configuration:

```ruby
# Octokey example configuration

# You can generate a suitable string for hmac scret by
# running $ head -c48 | base64 on the command line.
# Do not share your hmac secret with anyone, as it will significantly
# reduce the strength of Octokey if it is known.
Octokey::Config.hmac_secret = # a long random string.

# Which hostnames does your website run on?
#
# You may need to configure these differently in development than in
# production. There is a small risk of unnecessarily including localhost
# in this list; so try to remove it in production.
Octokey::Config.valid_hostnames = ['localhost', '*.testing.local']

# How should Octokey load the public keys associated with a given user?
#
# You should return an array of strings from this block.
Octokey::Config.public_keys do |username, opts|
  User.find_by_username(username).public_keys
end
```
