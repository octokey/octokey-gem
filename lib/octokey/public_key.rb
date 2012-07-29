class Octokey
  class PublicKey

    TYPE = "ssh-rsa"
    SSH_RSA_MINIMUM_MODULUS_SIZE = 768

    private
    attr_accessor :expected_type, :type, :e, :n, :invalid_buffer

    public

    # Wrap an existing public key.
    #
    # @param [OpenSSL::PKey::RSA] key
    # @return [Octokey::PublicKey]
    # @raise [ArgumentError] if the key was not an rsa key
    def self.from_key(key)
      raise ArgumentError, "Invalid key type" unless OpenSSL::PKey::RSA === key
      new.instance_eval do
        self.e = key.e
        self.n = key.n
        self.type = TYPE
        self
      end
    end

    # Extract a public key from a buffer.
    #
    # If parsing fails then the returned Octokey::PublicKey's .valid? method
    # will return false.
    #
    # @param [Octokey::Buffer] buffer
    # @param [String] (nil) expected_type
    # @return [Octokey::PublicKey]
    def self.from_buffer(buffer, expected_type = nil)
      new.instance_eval do
        begin 
          self.expected_type = expected_type
          self.type = buffer.scan_string
          if type == TYPE
            self.e, self.n = buffer.scan_all(:mpint, :mpint)
          end
        rescue Octokey::InvalidBuffer => e
          self.invalid_buffer = e.message
        end

        self
      end
    end

    # Parse the string representation of a public key.
    #
    # The string representation used matches exactly the format which ssh uses
    # to store public keys in the ~/.ssh/authorized_keys file:
    #  "ssh-rsa <base64-encoded-buffer>"
    #
    # If parsing fails then the returned Octokey::PublicKey's .valid? method
    # will return false.
    #
    # @param [String]  the string to parse
    # @return [Octokey::PublicKey]
    def self.from_string(string)
      if string =~ /\A([^\s]+)\s+([^\s]+)/
        from_buffer(Octokey::Buffer.new($2), $1)
      else
        new.instance_eval do
          self.invalid_buffer = "Badly formatted public key"
          self
        end
      end
    end

    # Is this a correct valid public key?
    #
    # If this method returns false, the .errors method can be used to get a
    # more detailed error message.
    #
    # @return [Boolean]
    def valid?
      errors == []
    end

    # What was wrong with this public key?
    #
    # @return [Array<String>] the problems
    def errors
      if invalid_buffer
        [invalid_buffer]
      elsif expected_type && type != expected_type
        ["Public key type mismatch"]
      elsif type != TYPE
        ["Public key type unsupported"]
      elsif n.num_bits < SSH_RSA_MINIMUM_MODULUS_SIZE
        ["Public key too small"]
      else
        []
      end
    end

    # The OpenSSL::PKey::RSA version of this public key.
    #
    # @return [OpenSSL::PKey::RSA]  the public key
    # @raise [RuntimeError]  if the Octokey::PublicKey is not valid
    def public_key
      raise RuntimeError, "Tried to read invalid public_key" unless valid?
      key = OpenSSL::PKey::RSA.new
      key.e = e
      key.n = n
      key
    end

    # Store the public key into a buffer.
    #
    # @return [Octokey::Buffer]
    def to_buffer
      Octokey::Buffer.new.
        add_string(type).
        add_mpint(e).
        add_mpint(n)
    end

    # Get the string representation of this key.
    # 
    # @return [String]
    def to_s
      "#{type.to_s} #{to_buffer.to_s}"
    end

    # Get a string representation of this key suitable for use while debugging.
    #
    # @return [String]
    def inspect
      "#<Octokey::PublicKey #{to_s.inspect}>"
    end

    # Return a hash code suitable for storing public keys in a ruby Hash.
    #
    # @return [Fixnum]
    def hash
      to_s.hash ^ self.class.hash
    end

    # Compare this public key to another.
    #
    # @return [Boolean]
    def ==(other)
      self.hash == other.hash && self.to_s == other.to_s
    end
    alias_method :eql?, :==
  end
end