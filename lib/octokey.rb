require 'ipaddr'
require 'securerandom'
require 'uri'

require File.expand_path('octokey/buffer', File.dirname(__FILE__))
require File.expand_path('octokey/config', File.dirname(__FILE__))
require File.expand_path('octokey/challenge', File.dirname(__FILE__))
require File.expand_path('octokey/public_key', File.dirname(__FILE__))
require File.expand_path('octokey/auth_request', File.dirname(__FILE__))

class Octokey
  # Raised when you try and access details of an invalid octokey request.
  # If you always check .can_log_in? or .can_sign_up? first, you should not
  # see this exception.
  class InvalidRequest < StandardError; end

  # Raised if an Octokey::Buffer is invalid. This is usually caught by Octokey
  # so you will only need to catch it if you are parsing buffers yourself.
  class InvalidBuffer < InvalidRequest; end

  # Create a new challenge.
  #
  # Once created, the challenge should be sent to the client for it to sign.
  #
  # The client_ip address is included in the outgoing challenge to verify that
  # incoming login requests came from the same client as requested the challenge.
  #
  # @param [Hash] opts
  # @option opts [String,IPAddr] client_ip  The IP address of the client.
  # @return [String]  The Base64 encoded challenge.
  def self.new_challenge(opts)
    Octokey::Challenge.generate(opts).to_s
  end

  # Sign a challenge.
  #
  # If you're acting as an Octokey client, then you use this function to turn
  # a challenge that you've been issued into an auth_request to send back to the
  # server.
  #
  # @param [String] challenge  The base64-encoded challenge issued by the server.
  # @param [Hash] opts
  # @option [String] :username  Which username would you like to log in as.
  # @option [String] :request_url  Which page would you like to log in to.
  # @option [OpenSSL::PKey::RSA] :private_key  The private key with which to sign the challenge.
  # @return [String]  The Base64 encoded auth_request
  def self.sign_challenge(challenge, opts)
    Octokey::AuthRequest.generate({:challenge => challenge}.merge(opts)).to_s
  end

  # Handle a new Octokey request.
  #
  # The options passed in to this method will be passed in as the second parameter to
  # all the configuration blocks.
  #
  # @param [String] auth_request  The Base64 encoded auth request from the client.
  # @param [Hash] opts
  # @option [String] :username  The username that the user wishes to log in as.
  # @option [String,IPAddr] :client_ip  The ip address of the client.
  def initialize(auth_request, opts)
    raise ArgumentError, "no :username given" unless opts[:username]
    raise ArgumentError, "no :client_ip given" unless opts[:client_ip]
    @opts = opts.dup
    @auth_request = Octokey::Config.get_auth_request(auth_request, opts)
  end

  # Should the user be allowed to log in?
  #
  # If this method returns true then you can assume that the user with :username
  # is actually the user who's trying to log in.
  #
  # @return [Boolean]
  def can_log_in?
    valid_auth_request? && valid_public_key?
  end

  # Should the user be allowed to sign up?
  #
  # If this method returns true then you can store the public_key against the
  # user's username. Future logins by that user will use that to verify that the user
  # trying to log in has access to the private key that corresponds to this public key.
  #
  # @return [Boolean]
  def can_sign_up?
    valid_auth_request?
  end

  # Was the failure to log in or sign up transient?
  #
  # This will return true if the client may be able to log in simply by requesting
  # a new challenge from the server and retrying the auth_request.
  #
  # @return [Boolean]
  def should_retry?
    !valid_auth_request? && auth_request.valid_ignoring_challenge?(opts)
  end

  # Get the username used for this request.
  #
  # You must validate that the username meets your requirements for a valid username,
  # Octokey allows any username (for example the empty string, the string "\r\n"). You might
  # want to enforce that the username is an email address, or contains only visible characters.
  #
  # @return [String] username
  # @raise [InvalidRequest] if neither .can_sign_up? nor .can_log_in?
  def username
    raise InvalidRequest, "Tried to get username from invalid octokey" unless valid_auth_request?
    auth_request.username
  end

  # Get the public_key used for this request.
  #
  # You will need this when handling a sign up request for the user in order to
  # extract the public key needed to log in.
  #
  # The format of the returned public key is exactly the same as used by SSH in the
  # ~/.authorized_keys file. That format can be parsed by {Octokey::PublicKey} if you
  # need more information.
  #
  # @return [String]
  # @raise [InvalidRequest] if neither .can_sign_up? nor .can_log_in?
  def public_key
    raise InvalidRequest, "Tried to get username from invalid octokey" unless valid_auth_request?
    auth_request.public_key.to_s
  end

  private
  attr_accessor :opts, :auth_request

  # Is the auth_request valid?
  # @return [Boolean]
  def valid_auth_request?
    @valid ||= auth_request.valid?(opts)
  end

  # Is the public key used to sign the auth request one of those that belongs to the username?
  # @return [Boolean]
  def valid_public_key?
    strings = Octokey::Config.get_public_keys(opts[:username], opts)
    public_keys = strings.map{ |string| Octokey::PublicKey.from_string(string) }
    raise ArgumentError, "Invalid public key returned to Octokey for #{username}" unless public_keys.all(:valid?)
    public_keys.include?(auth_request.public_key)
  end
end
