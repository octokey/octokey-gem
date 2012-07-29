class Octokey
  class Config
    def self.hmac_secret=(secret)
      @hmac_secret = secret.to_str
    end

    def self.valid_hostnames=(hostnames)
      @valid_hostnames = hostnames.to_ary
    end

    def self.public_keys(&block)
      @public_keys_block = block
    end

    def self.challenge(&block)
      @challenge_block = block
    end

    def self.auth_request(&block)
      @auth_request_block = block
    end

    def self.hmac_secret
      @hmac_secret or raise "You must configure Octokey::Config.hmac_secret = FOO"
    end

    def self.valid_hostnames
      @valid_hostnames or raise "You must configure Octokey::Config.valid_hostnames = ['example.com']"
    end

    def self.get_challenge(string, opts)
      @challenge_block.call(string, opts)
    end

    def self.get_auth_request(string, opts)
      @auth_request_block.call(string, opts)
    end

    def self.get_public_keys(username, opts)
      @get_public_keys_block.call(username, opts)
    end

    challenge do |string, opts|
      Octokey::Challenge.from_string(string)
    end

    auth_request do |string, opts|
      Octokey::AuthRequest.from_string(string)
    end

    public_keys do |username, opts|
      raise NotImplementedError, "You must configure Octokey::Config.get_public_keys{ |username, opts| [] }"
    end
  end
end