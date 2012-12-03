class Octokey
  class KeyFragment
    def self.split(private_key)
      # we don't want halves to end up too small relative to their original keys
      begin
        half = OpenSSL::BN.rand_range(private_key.d)
      end while private_key.d.num_bits - half.num_bits > 4

      [new(:half_d => half, :public_key => private_key.public_key),
       new(:half_d => private_key.d - half, :public_key => private_key.public_key)]
    end

    def initialize(options)
      @half_d = options[:half_d] or raise "no d given"
      @public_key = options[:public_key] or raise "no public key given"
    end

    def encrypt_some(string, so_far=nil)
      string.force_encoding('BINARY')

      puts pkcs1_pad(string).size

      m = OpenSSL::BN.new(pkcs1_pad(string), 2)

      # FIXME: vulnerable to timing attacks
      c = m.mod_exp(half_d, public_key.n)

      if so_far
        so_far = OpenSSL::BN.new(so_far, 2)
        c = c.mod_mul(so_far, public_key.n)
      end

      c.to_s(2)
    end

    def pkcs1_pad(string)
      # Ensure that the message has a lot of \xFFs near the front
      # so it's not going to be a small number.
      if string.size > bytelength - 11
        raise "refusing to encoding string, it's too long: (max length is #{bytelength - 11})"
      end
      padding_size = bytelength - string.size - 3
      "\x00\x01" + ("\xff" * padding_size) + "\x00" + string
    end

    private

    attr_reader :half_d, :public_key

    def bytelength
      @bytelength ||= public_key.n.to_s(2).size
    end
  end
end
