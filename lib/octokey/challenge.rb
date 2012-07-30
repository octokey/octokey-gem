class Octokey
  # In order to verify that the client is in posession of the private key that
  # corresponds to the public key that it claims to own, we need to give it a
  # string to sign.
  #
  # In order for the scheme to be as secure as possible, the challenges should
  # be unique, unguessable and unforgeable. This prevents an attacker who can
  # somehow generate valid signatures from being able to pre-compute any.
  #
  # Additionally, challenges should expire after a short time. This both makes
  # it harder for the attacker that can generate valid signatures (they have to
  # do it quickly), and also protects users in case logs of signed auth requests
  # are "leaked" as the attackers will not be able to re-use any of them.
  #
  # The client_ip is included in the challenge to make it harder for attackers
  # who can read logs in real-time to use challenges; they'd have to be able to
  # forge their IP address too. This doesn't provide any protection against a
  # full man-in-the-middle attack, because such an attacker could likely forge
  # the client ip address anyway.
  #
  # If you're willing to trade architectural simplicity for extra security, you
  # should consider using a database to store issued challenges and marking them
  # as "invalid" as soon as they are first attempted. This helps further with
  # the attacks mentioned above.
  #
  class Challenge
    # Which version of challenges is supported.
    CHALLENGE_VERSION = 3
    # How many bytes of random data should be included.
    RANDOM_SIZE = 32
    # Hash algorithm to use in the HMAC
    HMAC_ALGORITHM = "sha1"
    # The maximum age of a valid challenge (milliseconds)
    MAX_AGE = 5 * 60_000
    # The minimum age of a valid challenge (milliseconds)
    MIN_AGE = -30_000

    private
    attr_accessor :version, :timestamp, :client_ip, :random, :digest, :invalid_buffer

    public

    # Parse a challenge.
    #
    # The resulting challenge may not be valid! You should call {#valid?} on it before
    # making assumptions.
    #
    # @param [String] string  A return value of {Octokey::Challenge.to_s}
    # @return [Octokey::Challenge]
    # @raise [Octokey::InvalidBuffer]
    #
    def self.from_string(string)
      buffer = Octokey::Buffer.new(string)
      new.instance_eval do
        begin
          self.version = buffer.scan_uint8
          if version == CHALLENGE_VERSION
            self.timestamp, self.client_ip, self.random, self.digest =
              buffer.scan_all(:timestamp, :ip, :varbytes, :varbytes)
          end
        rescue InvalidBuffer => e
          self.invalid_buffer = e.message
        end

        self
      end
    end

    # Generate a new challenge.
    #
    # @param [Hash] opts
    # @option opts [IPAddr, String] :client_ip  The IP address of the client
    # @option opts [Time] :current_time  (Time.now) The current time
    # @return [Octokey::Challenge]
    #
    def self.generate(opts = {})
      new.instance_eval do
        expected_ip  = IPAddr(opts[:client_ip])
        current_time = opts[:current_time] || Time.now

        self.version = CHALLENGE_VERSION
        self.timestamp = current_time.to_i * 1000 + current_time.usec / 1000
        self.client_ip = expected_ip
        self.random = SecureRandom.random_bytes(RANDOM_SIZE)
        self.digest = expected_digest
        self
      end
    end

    # Is this challenge valid?
    #
    # @param [Hash] opts
    # @option opts [IPAddr, String] :client_ip  The IP address of the client
    # @option opts [Time] :current_time  (Time.now) The current time
    # @return [Boolean]
    #
    def valid?(opts)
      errors(opts) == []
    end


    # What errors were encountered parsing this challenge?
    #
    # @param [Hash] opts
    # @option opts [IPAddr, String] :client_ip  The IP address of the client
    # @option opts [Time] :current_time  (Time.now) The current time
    # @return [Array<String>]
    #
    def errors(opts)
      expected_ip  = IPAddr(opts[:client_ip])
      current_time = opts[:current_time] || Time.now
      current_time = current_time.to_i * 1000 + current_time.usec / 1000

      return [invalid_buffer] unless invalid_buffer.nil?
      return ["Challenge version mismatch"] unless version == CHALLENGE_VERSION

      errors = []
      errors << "Challenge too old"          unless current_time < timestamp + MAX_AGE
      errors << "Challenge too new"          unless current_time > timestamp + MIN_AGE
      errors << "Challenge IP mismatch"      unless client_ip == expected_ip
      errors << "Challenge random mismatch"  unless random.size == RANDOM_SIZE
      errors << "Challenge HMAC mismatch"    unless digest == expected_digest

      errors
    end

    # Return a the challenge serialized into a buffer.
    #
    # @return [String]
    def to_buffer
      unsigned_buffer.
        add_varbytes(digest)
    end

    # Return a Base64-encoded copy of this challenge serialized into a buffer.
    #
    # @return [String]
    def to_s
      to_buffer.to_s
    end

    # Return a string suitable for identifying this challenge while debugging.
    #
    # @return [String]
    def inspect
      "#<Octokey::Challenge @version=#{version.inspect} @timestamp=#{timestamp.inspect}" +
        "@client_ip=#{client_ip.inspect}>"
    end

    private

    # The digest calculated from the remainder of the challenge
    #
    # @return [String]
    def expected_digest
      OpenSSL::HMAC.digest(HMAC_ALGORITHM, Octokey::Config.hmac_secret, unsigned_buffer.raw)
    end

    # A buffer containing everything except the signature
    #
    # @return [Octokey::Buffer]
    def unsigned_buffer
      Octokey::Buffer.new.
        add_uint8(version).
        add_timestamp(timestamp).
        add_ip(client_ip).
        add_varbytes(random)
    end

    # Convert a provided parameter into an IPAddr.
    #
    # @param [IPAddr, String] x
    # @return [IPAddr]
    # @raise [ArgumentError]
    def IPAddr(x)
      x && IPAddr.new(x.to_s) or raise ArgumentError, "no client IP given"
    end
  end
end
