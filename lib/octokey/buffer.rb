require 'base64'
class Octokey
  # Buffers are used throughout Octokey to provide a bijective serialization format.
  # For any valid buffer, there's exactly one valid object, and vice-versa.
  #
  # Mostly we used Base64-encoded buffers to avoid problems with potentially 8-bit
  # unsafe channels. You should take care not to perform any operations on the Base64
  # encoded form as there are many accepted formats for Base64-encoding a given string.
  #
  # In the current implementation, reading out of a buffer is a destructive operation,
  # you should first .dup any buffer that you want to read more than once.
  class Buffer
    attr_accessor :buffer, :invalid_buffer

    # to avoid DOS caused by duplicating enourmous buffers,
    # we limit the maximum size of any string stored to 100k
    MAX_STRING_SIZE = 100 * 1024

    # Create a new buffer from raw bits.
    #
    # @param [String] raw
    def self.from_raw(raw = "")
      ret = new
      ret.buffer = raw.dup
      ret.buffer.force_encoding('BINARY') if ret.buffer.respond_to?(:force_encoding)
      ret
    end

    # Create a new buffer from a Base64-encoded string.
    # @param [String] string
    def initialize(string = "")
      self.buffer = Base64.decode64(string || "")
      buffer.force_encoding('BINARY') if buffer.respond_to?(:force_encoding)
      self.invalid_buffer = "Badly formatted Base64" unless to_s == string
    end

    # Get the underlying bits contained in this buffer.
    # @return [String]
    def raw
      buffer
    end
    
    # Get the canonical Base64 representation of this buffer.
    # @return [String]
    def to_s
      Base64.encode64(buffer).gsub("\n", "")
    end

    # Get a string that describes this buffer suitably for debugging.
    # @return [String]
    def inspect
      "#<Octokey::Buffer @buffer=#{to_s.inspect}>"
    end

    # Is this buffer empty?
    # @return [Boolean]
    def empty?
      buffer.empty?
    end

    # Add an unsigned 8-bit number to this buffer
    # @param [Fixnum] x
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer] if x is not a uint8
    def add_uint8(x)
      raise InvalidBuffer, "Invalid uint8: #{x}" if x < 0 || x >= 2 ** 8
      buffer << [x].pack("C")
      self
    end

    # Destructively read an unsigned 8-bit number from this buffer
    # @return [Fixnum]
    # @raise [Octokey::InvalidBuffer]
    def scan_uint8
      scan(1).unpack("C").first
    end

    # Add a timestamp to this buffer
    #
    # Times are stored to millisecond precision.
    #
    # @param [Time] time
    # @return [Octokey::Buffer] self
    def add_time(time)
      seconds, millis = [time.to_i, (time.usec / 1000.0).round]
      add_uint64(seconds * 1000 + millis)
      self
    end

    # Destructively read a timestamp from this buffer
    #
    # Times are stored to millisecond precision
    #
    # @return [Time]
    # @raise [Octokey::InvalidBuffer]
    def scan_time
      raw = scan_uint64
      seconds, millis = [raw / 1000, raw % 1000]
      Time.at(seconds) + (millis / 1000.0)
    end

    # Add an IPv4  or IPv6 address to this buffer
    #
    # @param [IPAddr] ipaddr
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer] not a valid IP address
    def add_ip(ipaddr)
      if ipaddr.ipv4?
        add_uint8(4)
        buffer << ipaddr.hton
      elsif ipaddr.ipv6?
        add_uint8(6)
        buffer << ipaddr.hton
      else
        raise InvalidBuffer, "Unsupported IP address: #{ipaddr.to_s}"
      end
      self
    end

    # Destructively read an IPv4 or IPv6 address from this buffer.
    # @return [IPAddr]
    # @raise [Octokey::InvalidBuffer]
    def scan_ip
      type = scan_uint8
      case type
      when 4
        IPAddr.new_ntoh scan(4)
      when 6
        IPAddr.new_ntoh scan(16)
      else
        raise InvalidBuffer, "Unknown IP family: #{type.inspect}"
      end
    end

    # Add a length-prefixed number of bytes to this buffer
    # @param [String] bytes
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer] if there are too any bytes
    def add_varbytes(bytes)
      bytes.force_encoding('BINARY') if bytes.respond_to?(:force_encoding)
      size = bytes.size
      raise InvalidBuffer, "Too much length: #{size}" if size > MAX_STRING_SIZE
      add_uint32 size
      buffer << bytes
      self
    end

    # Destructively read a length-prefixed number of bytes from this buffer
    # @return [String] bytes
    # @raise [Octokey::InvalidBuffer]
    def scan_varbytes
      size = scan_uint32
      raise InvalidBuffer, "Too much length: #{size}" if size > MAX_STRING_SIZE
      scan(size)
    end

    # Add a length-prefixed number of bytes of UTF-8 string to this buffer
    # @param [String] string
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer]  if the string is not utf-8
    def add_string(string)
      add_varbytes(validate_utf8(string))
    end

    # Destructively read a length-prefixed number of bytes of UTF-8 string
    # @return [String] with encoding == 'utf-8' on ruby-1.9
    # @raise [Octokey::InvalidBuffer]
    def scan_string
      validate_utf8(scan_varbytes)
    end

    # Add the length-prefixed contents of another buffer to this one.
    # @param [Octokey::Buffer] buffer
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer]
    def add_buffer(buffer)
      add_varbytes buffer.raw
      self
    end

    # Destrictively read a length-prefixed buffer out of this one.
    # @return [Octokey::Buffer]
    # @raise [Octokey::InvalidBuffer]
    def scan_buffer
      Octokey::Buffer.from_raw scan_varbytes
    end

    # Add an unsigned multi-precision integer to this buffer
    # @param [OpenSSL::BN,Fixnum] x
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer] if x is negative or enourmous
    def add_mpint(x)
      raise InvalidBuffer, "Invalid mpint: #{mpint.inspect}" if x < 0
      bytes = OpenSSL::BN.new(x.to_s, 10).to_s(2)
      bytes = "\x00" + bytes if bytes.bytes.first >= 0x80
      add_varbytes(bytes)
      self
    end

    # Destructively read an unsigned multi-precision integer from this buffer
    # @return [OpenSSL::BN]
    # @raise [Octokey::InvalidBuffer]
    def scan_mpint
      raw = scan_varbytes

      first, second = raw.bytes.first(2)

      # ensure only positive numbers with no superflous leading 0s
      if first >= 0x80 || first == 0x00 && second < 0x80
        raise InvalidBuffer, "Badly formatted mpint"
      end

      OpenSSL::BN.new(raw, 2)
    end

    # Destructively read a public key from this buffer
    #
    # NOTE: the returned public key may not be valid, you must call
    # .valid? on it before trying to use it.
    #
    # @return [Octokey::PublicKey]
    # @raise [Octokey::InvalidBuffer]
    def scan_public_key
      Octokey::PublicKey.from_buffer(scan_buffer)
    end

    # Add a public key to this buffer
    # @param [Octokey::PublicKey] public_key
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer]
    def add_public_key(public_key)
      add_buffer public_key.to_buffer
    end

    # Destructively read the entire buffer.
    #
    # It's strongly recommended that you use this method to parse buffers, as it
    # remembers to verify that the buffer doesn't contain any trailing bytes; and
    # will return nothing if the buffer is invalid, so your code doesn't have to 
    # deal with half-parsed buffers.
    #
    # The tokens should correspond to the scan_X methods defined here. For example:
    #  type, e, n = buffer.scan_all(:string, :mpint, :mpint)
    # is equivalent to:
    #  type, e, n, _ = [buffer.scan_string, buffer.scan_mpint, buffer.scan_mpint,
    #                   buffer.scan_end]
    #
    # @param [Array<Symbol>] tokens
    # @return [Array<Object>]
    # @raise [Octokey::InvalidBuffer]
    def scan_all(*tokens)
      ret = tokens.map do |token|
        raise "invalid token type: #{token.inspect}" unless respond_to?("scan_#{token}")
        send("scan_#{token}")
      end

      scan_end
      ret
    end

    # Verify that the buffer has been completely scanned.
    # @raise [Octokey::InvalidBuffer] if there is still buffer to read.
    def scan_end
      raise InvalidBuffer, "Buffer too long" unless empty?
    end

    private

    # Destructively read bytes from the front of this buffer.
    # @param [Fixnum] n
    # @return [String]
    # @raise [Octokey::InvalidBuffer]
    def scan(n)
      raise InvalidBuffer, invalid_buffer if invalid_buffer
      ret, buf = [buffer[0...n], buffer[n..-1]]
      if ret.size < n || !buf
        raise InvalidBuffer, "Buffer too short"
      end
      self.buffer = buf
      ret
    end

    # Add an unsigned 32-bit number to this buffer
    # @param [Fixnum] x
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer] if x is not a uint32
    def add_uint32(x)
      raise InvalidBuffer, "Invalid uint32: #{x}" if x < 0 || x >= 2 ** 32
      buffer << [x].pack("N")
      self
    end

    # Destructively read an unsigned 32-bit number from this buffer
    # @return [Fixnum]
    # @raise [Octokey::InvalidBuffer]
    def scan_uint32
      scan(4).unpack("N").first
    end

    # Add an unsigned 64-bit number to this buffer
    # @param [Fixnum] x
    # @return [Octokey::Buffer] self
    # @raise [Octokey::InvalidBuffer] if x is not a uint64
    def add_uint64(x)
      raise InvalidBuffer, "Invalid uint64: #{x}" if x < 0 || x >= 2 ** 64
      add_uint32(x >> 32 & 0xffff_ffff)
      add_uint32(x & 0xffff_ffff)
      self
    end

    # Destructively read an unsigned 64-bit number from this buffer
    # @return [Fixnum]
    # @raise [Octokey::InvalidBuffer]
    def scan_uint64
      (scan_uint32 << 32) + scan_uint32
    end

    # Check whether a string is valid utf-8
    # @param [String] string
    # @return [String] string
    # @raise [Octokey::InvalidBuffer] invalid utf-8
    def validate_utf8(string)
      if string.respond_to?(:force_encoding)
        string.force_encoding('UTF-8')
        raise InvalidBuffer, "String not UTF-8" unless string.valid_encoding?
        string
      else
        require 'iconv'
        begin
          Iconv.conv('utf-8', 'utf-8', string)
        rescue Iconv::Failure
          raise InvalidBuffer, "String not UTF-8"
        end
      end
    end
  end
end
