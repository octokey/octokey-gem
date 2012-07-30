class Octokey
  # All configuration for Octokey is stored here.
  class Config
    # Configure the hmac_secret for Octokey.
    #
    # This should be a long random string, such as might be generated with:
    # $ head -c48 /dev/random | base64
    #
    def self.hmac_secret=(secret)
      @hmac_secret = secret.to_str
    end

    # Which hostnames does your website use?
    #
    # This should be an array, for example ["example.com", "*.example.org"]
    # *.example.org will match bar.example.org, foo.bar.example.org, etc.
    # example.com will only match example.com
    def self.valid_hostnames=(hostnames)
      @valid_hostnames = hostnames.to_ary
    end

    # Given a username which public keys should they be allowed to log in with
    #
    # Your block should only return strings that you obtained through Octokey#public_key
    # as part of the sign up flow. They have the same format as ssh keys found in the
    # ~/.authorized_keys file.
    #
    # @example
    #   Octokey::Config.public_keys do |username, opts|
    #     User.find_by_username(username).public_keys
    #   end
    #
    def self.public_keys(&block)
      @public_keys_block = block
    end

    # Given a string, get an Octokey::Challenge.
    #
    # NOTE: this is an advanced feature, you only need to implement this method
    # if you subclass Octokey::Challenge.
    def self.challenge(&block)
      @challenge_block = block
    end

    # Given a string, get an Octokey::AuthRequest.
    #
    # NOTE: this is an advanced feature, you only need to implement this method
    # if you subclass Octokey::AuthRequest.
    def self.auth_request(&block)
      @auth_request_block = block
    end

    # Get the HMAC secret previously configured
    # @return [String]
    def self.hmac_secret
      @hmac_secret or raise "You must configure Octokey::Config.hmac_secret = FOO"
    end

    # Get the valid hostnames previously configured
    # @return [Array<String>]
    def self.valid_hostnames
      @valid_hostnames or raise "You must configure Octokey::Config.valid_hostnames = ['example.com']"
    end

    # Get a new Octokey::Challenge instance
    # @param [String] string  The Base64-encoded challenge
    # @param [Hash] opts  Passed to Octokey.new
    # @return [Octokey::Challenge]
    def self.get_challenge(string, opts)
      @challenge_block.call(string, opts)
    end

    # Get a new Octokey::AuthRequest instance
    # @param [String] string  The Base64-encoded auth_request
    # @param [Hash] opts  Passed to Octokey.new
    # @return [Octokey::AuthRequest]
    def self.get_auth_request(string, opts)
      @auth_request_block.call(string, opts)
    end

    # Get the public keys associated with the given username.
    # @param [String] username  The claimed username
    # @param [Hash] opts  Passed to Octokey.new
    # @return [Array<String>]
    def self.get_public_keys(username, opts)
      @public_keys_block.call(username, opts)
    end

    challenge do |string, opts|
      Octokey::Challenge.from_string(string)
    end

    auth_request do |string, opts|
      Octokey::AuthRequest.from_string(string)
    end

    public_keys do |username, opts|
      raise NotImplementedError, "You must configure Octokey::Config.public_keys{ |username, opts| [] }"
    end
  end
end