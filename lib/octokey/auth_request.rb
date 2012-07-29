class Octokey
  class AuthRequest
    SERVICE_NAME      = "octokey-auth"
    AUTH_METHOD       = "publickey"
    SIGNING_ALGORITHM = "ssh-rsa"
    DIGEST_ALGORITHM  = "SHA1"

    attr_accessor :challenge_buffer, :request_url, :username, :service_name,
                  :auth_method, :signing_algorithm, :public_key, :signature_buffer,
                  :invalid_buffer

    # Given a challenge and a private key, generate an auth request.
    #
    # @param [Hash] opts
    # @option opts [String] :request_url
    # @option opts [String] :username
    # @option opts [String] :challenge  The base64-encoded challenge
    # @option opts [OpenSSL::PKey::RSA] :private_key
    # @return [Octokey::AuthRequest]
    def self.generate(opts)
      private_key = opts[:private_key] or raise ArgumentError, "No private_key given"
      challenge = opts[:challenge] or raise ArgumentError, "No challenge given"

      new.instance_eval do
        self.challenge_buffer = Octokey::Buffer.new(challenge)
        self.request_url = opts[:request_url] or raise ArgumentError, "No request_url given"
        self.username = opts[:username] or raise ArgumentError, "No username given"
        self.service_name = SERVICE_NAME
        self.auth_method = AUTH_METHOD
        self.signing_algorithm = SIGNING_ALGORITHM
        self.public_key = Octokey::PublicKey.from_key(private_key.public_key)
        self.signature_buffer = signature_buffer_with(private_key)

        self
      end
    end

    # Parse an auth request sent from the client.
    #
    # @param[String]  The base64-encoded auth request from the client.
    # @return [Octokey::AuthRequest]
    def self.from_string(string)
      buffer = Octokey::Buffer.new(string)
      new.instance_eval do
        begin
          self.challenge_buffer, self.request_url, self.username,
          self.service_name, self.auth_method, self.signing_algorithm,
          self.public_key, self.signature_buffer =
            buffer.scan_all(
              :buffer, :string, :string,
              :string, :string, :string,
              :public_key, :buffer)
        rescue Octokey::InvalidBuffer => e
          self.invalid_buffer = e.message
        end

        self
      end
    end

    # Get any errors ignoring those caused by the challenge.
    #
    # @param [Hash] opts
    # @return [Array<String>]
    def errors_ignoring_challenge(opts)
      return [invalid_buffer] if invalid_buffer
      errors = []

      errors += request_url_errors(opts)
      errors << "Auth request username mismatch"             unless username == opts[:username]
      errors << "Auth request service name mismatch"         unless service_name == SERVICE_NAME
      errors << "Auth request auth method unsupported"       unless auth_method == AUTH_METHOD
      errors << "Auth request signing algorithm unsupported" unless signing_algorithm == SIGNING_ALGORITHM

      if public_key.valid?
        errors += signature_errors(public_key.public_key, signature_buffer.dup)
      else
        errors += public_key.errors
      end

      errors
    end

    # Get any errors caused by the challenge. 
    #
    # @param [Hash] opts
    # @return [Array<String>]
    def challenge_errors(opts)
      return [] if invalid_buffer
      Octokey::Config.get_challenge(challenge_buffer.to_s, opts).errors(opts)
    end

    # Get all the error for this auth request.
    #
    # @param [Hash] opts
    # @return [Array<String>]
    def errors(opts)
      errors_ignoring_challenge(opts) + challenge_errors(opts)
    end

    # If the challenge was valid, would this auth request be valid?
    #
    # This can be used to check whether the auth request should be retried.
    #
    # @param [Hash] opts
    # @return [Boolean]
    def valid_ignoring_challenge?(opts)
      errors_ignoring_challenge(opts) == []
    end

    # Is this auth request valid?
    #
    # @param [Hash] opts
    # @return [Boolean]
    def valid?(opts)
      errors(opts) == []
    end

    def to_s
      unsigned_buffer.add_buffer(signature_buffer).to_s
    end

    def inspect
      "#<Octokey::AuthRequest #{to_s.inspect}>"
    end

    private

    # What are the problems with the signature? 
    #
    # @param [OpenSSL::PKey::RSA] the public key
    # @param [Octokey::Buffer] the signature buffer
    # @return [Array<String>]
    def signature_errors(key, signature_buffer)
      algorithm_used, signature = signature_buffer.scan_all(:string, :varbytes)

      errors = []
      errors << "Signature type mismatch" unless algorithm_used == signing_algorithm
      errors << "Signature mismatch"      unless key.verify(OpenSSL::Digest::SHA1.new, signature, unsigned_buffer.raw)
      errors

    rescue Octokey::InvalidBuffer => e
      ["Signature #{e.message}"]
    end

    # What are the problems with the request url?
    #
    # @param [Hash] opts
    # @return [Array<String>]
    def request_url_errors(opts)
      url = URI.parse(request_url)

      valid_hostname = Octokey::Config.valid_hostnames.any? do |hostname|
        if hostname[/\A\*\.(.*)\z/]
          url.host.end_with?($1)
        else
          url.host == hostname
        end
      end

      errors = []
      errors << "Request url insecure" unless url.scheme == "https"
      errors << "Request url mismatch" unless valid_hostname
      errors

    rescue URI::InvalidURIError
      ["Auth request url invalid"]
    end

    # Get the buffer containing everything other than the signature.
    #
    # @return [Octokey::Buffer]
    def unsigned_buffer
      Octokey::Buffer.new.
        add_buffer(challenge_buffer).
        add_string(request_url).
        add_string(username).
        add_string(service_name).
        add_string(auth_method).
        add_string(signing_algorithm).
        add_buffer(public_key.to_buffer)
    end

    # Get the signature buffer using the given key.
    #
    # @param [OpenSSL::PKey::RSA] the private key
    # @return [Octokey::Buffer]
    def signature_buffer_with(private_key)
      Octokey::Buffer.new.
        add_string(SIGNING_ALGORITHM).
        add_varbytes(private_key.sign(OpenSSL::Digest::SHA1.new, unsigned_buffer.raw))
    end
  end
end
