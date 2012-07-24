require File.expand_path('octokey/buffer', File.dirname(__FILE__))
require File.expand_path('octokey/challenge', File.dirname(__FILE__))
require File.expand_path('octokey/public_key', File.dirname(__FILE__))
require File.expand_path('octokey/auth_request', File.dirname(__FILE__))

require 'ipaddr'
require 'securerandom'
require 'uri'

class Octokey

  CHALLENGE_VERSION = 2
  SERVICE_NAME      = "octokey-auth"
  AUTH_METHOD       = "publickey"
  SIGNING_ALGORITHM = "ssh-rsa"
  DIGEST_ALGORITHM  = "SHA1"
  SSH_RSA_MINIMUM_MODULUS_SIZE = 768

  class InvalidRequest < StandardError; end
  class InvalidBuffer < InvalidRequest; end

  # Set the hmac_secret for Octokey.
  #
  # This is used to sign challenges to prove that they were issued by us.
  #
  # You can generate a suitable token to use as an hmac_secret from the
  # command line:
  #
  # $ head -c 48 /dev/random | base64
  #
  # @param [String] hmac_secret
  def self.hmac_secret=(hmac_secret)
    @hmac_secret = hmac_secret
    @hmac_secret_fingerprint = nil
  end

  # Get a challenge for signing in.
  #
  # The client will include this challenge in their octokey auth request when
  # they log in. It hopefully provides some security against replay attacks by
  # ensuring that if a signed auth-request is stolen, it is only valid in a
  # limited set of circumstances.
  #
  # Please be careful when obtaining a client IP address that you aren't getting
  # the IP address of an upstream proxy, and that you aren't trusting X-Forwarded-For
  # headers that you shouldn't be.
  #
  # @option opts [String] :client_ip  The IP address of the current client.
  # @option opts [Time] :time  (Time.now)
  #
  # @return [String]
  def self.new_challenge(opts = {})
    Octokey::Challenge.generate(opts).to_s
  end

  # Attempt to login with the given auth_request.
  #
  # @param [String] auth_request  The string sent by the Octokey client.
  # @option opts [String] :client_ip  The IP address of the client (see {.new_challenge)}
  # @option opts [Array<String>] :valid_hostnames  The list of hostnames which clients may
  #                                                log in from.
  # @option opts [Time] :time  (Time.now)
  #
  # @yield [String] username  The block should (when given a username) return a list of
  #                           public keys that are associated with that users account.
  #
  #                           NOTE: Do not assume that the username passed to the block
  #                           is logged in. The block is necessarily called before we know
  #                           this.
  #
  # @return [String] username  The user who successfully authenticated.
  # @raise [InvalidRequest]  If the login failed for some reason.
  def self.login(auth_request, opts = {}, &block)
    raise ArgumentError, "No public key lookup block given to login" unless block_given?

    username, public_key = signup(auth_request, opts)
    valid_public_keys = block.call(username)
    valid_public_keys.map!{ |public_key| format_public_key(unformat_public_key(public_key)) }

    unless valid_public_keys.include? public_key
      raise InvalidRequest, "Got unknown public key for #{username.inspect}: #{format_public_key(public_key).inspect}"
    end

    username
  end

  # Validate a signup request.
  #
  # @param [String] auth_request  The string sent by the Octokey client.
  # @option opts [String] :client_ip  The IP address of the client (see {.new_challenge)}
  # @option opts [Array<String>] :valid_hostnames  The list of hostnames which clients may
  #                                                log in from.
  # @option opts [Time] :time  (Time.now)
  #
  # @yield [String] username  The block should (when given a username) return a list of
  #                           public keys that are associated with that users account.
  #
  #                           NOTE: Do not assume that the username passed to the block
  #                           is logged in. The block is necessarily called before we know
  #                           this.
  #
  # @return [String] username  The username they tried to sign up with.
  # @return [String] public_key  Their public key
  # @raise [InvalidRequest]  If the login failed for some reason.
  def self.signup(auth_request, opts = {})
    client_ip = opts[:client_ip] or raise ArgumentError, "No :client_ip given to login"
    hostnames = opts[:valid_hostnames] or raise ArgumentError, "No :valid_hostnames given to login"
    time = opts[:time] || Time.now

    buffer = Octokey::Buffer.new(auth_request)

    challenge    = buffer.scan_string
    request_url  = buffer.scan_string
    username     = buffer.scan_string
    service_name = buffer.scan_string
    auth_method  = buffer.scan_string
    signing_alg  = buffer.scan_string
    public_key_b = buffer.scan_buffer
    signature_b  = buffer.scan_buffer

    public_key, errors = decode_public_key(public_key_b, "ssh-rsa")
    signature, sig_errors = decode_signature(signature_b, signing_alg)

    errors += sig_errors
    errors += Octokey::Challenge.from_string(challenge).errors(opts)

    hostname = URI.parse(request_url).host

    to_verify = Octokey::Buffer.new
    to_verify.add_string challenge
    to_verify.add_string request_url
    to_verify.add_string username
    to_verify.add_string service_name
    to_verify.add_string auth_method
    to_verify.add_string signing_alg
    to_verify.add_buffer public_key_b

    unless public_key.verify(OpenSSL::Digest::SHA1.new, signature, to_verify.raw)
      errors << "Signature was invalid"
    end

    unless buffer.empty?
      errors << "Request contained trailing bytes"
    end

    unless hostnames.include?(hostname)
      errors << "Request was for unknown hostname: #{hostname.inspect}"
    end

    unless service_name == SERVICE_NAME
      errors << "Incorrect service name: Got #{service_name.inspect}, expected: #{SERVICE_NAME.inspect}"
    end

    unless auth_method == AUTH_METHOD
      errors << "Incorrect auth type: Got #{auth_method.inspect}, expected: #{AUTH_TYPE.inspect}"
    end

    unless signing_alg == SIGNING_ALGORITHM
      errors << "Incorrect signing algorithm: Got #{signing_alg.inspect}, expected: #{SIGNING_ALGORITHM.inspect}"
    end

    unless errors.empty?
      raise InvalidRequest.new("Octokey request failed: #{errors.join(". ")}.")
    end

    [username, format_public_key(public_key)]
  end

  private

  def self.hmac_secret
    @hmac_secret or raise "No Octokey.hmac_secret set."
  end

  def self.hmac_secret_fingerprint
    @hmac_secret_fingerprint ||= OpenSSL::Digest::SHA1.digest(hmac_secret).bytes.first
  end

  def self.sign_challenge(challenge, username, request_url, private_key)
    to_sign = Octokey::Buffer.new
    to_sign.add_string challenge
    to_sign.add_string request_url
    to_sign.add_string username
    to_sign.add_string SERVICE_NAME
    to_sign.add_string AUTH_METHOD
    to_sign.add_string SIGNING_ALGORITHM
    to_sign.add_buffer encode_public_key(private_key)

    sigblob = private_key.sign(OpenSSL::Digest::SHA1.new, to_sign.raw)

    sig_buf = Octokey::Buffer.new
    sig_buf.add_string SIGNING_ALGORITHM
    sig_buf.add_string sigblob

    to_sign.add_buffer(sig_buf)

    to_sign.to_s
  end

  def self.decode_signature(buffer, expected_alg)
    buffer = buffer.dup

    signing_alg = buffer.scan_string
    signature = buffer.scan_varbytes

    errors = []

    unless buffer.empty?
      errors << "Signature contained trailing bytes"
    end

    unless signing_alg == expected_alg
      errors << "Signature algorithm mismatch: Got #{signing_alg.inspect}, expected: #{expected_alg.inspect}"
    end

    [signature, errors]
  rescue InvalidBuffer => e
    [nil, e.message]
  end

  def self.format_public_key(public_key)
    "ssh-rsa #{encode_public_key(public_key).to_s}"
  end

  def self.unformat_public_key(public_key)
    if public_key =~ /\A(ssh-rsa)\s+(.*)\z/
      key, errors = decode_public_key(Octokey::Buffer.new($2), $1)
      raise "Invalid public key: #{errors.join(". ")}." unless errors.empty?

      key
    else
      raise "Invalid public key: Got #{public_key.inspect}, expected \"ssh-rsa AAAAf...\""
    end
  end

  def self.encode_public_key(public_key)
    raise "not an RSA key: #{public_key}" unless OpenSSL::PKey::RSA === public_key
    buffer = Octokey::Buffer.new
    buffer.add_string "ssh-rsa"
    buffer.add_mpint public_key.e
    buffer.add_mpint public_key.n
    buffer
  end

  def self.decode_public_key(buffer, expected_type)
    buffer = buffer.dup

    key_type = buffer.scan_string
    e = buffer.scan_mpint
    n = buffer.scan_mpint

    errors = []

    unless buffer.empty?
      errors << "Public key contained trailing bytes"
    end

    unless key_type == expected_type
      errors << "Got unknown public key type: Got #{key_type.inspect}, expected: #{expected_type.inspect}"
    end

    unless n.num_bits > SSH_RSA_MINIMUM_MODULUS_SIZE
      errors << "RSA modulus too small: #{n.num_bits.inspect} < #{SSH_RSA_MINIMUM_MODULUS_SIZE.inspect}"
    end

    # TODO: verify size of modulus and exponent

    if errors == []
      key = OpenSSL::PKey::RSA.new
      key.e = e
      key.n = n
    end

    [key, errors]
  rescue InvalidBuffer => e
    [nil, e.message]
  end
end
