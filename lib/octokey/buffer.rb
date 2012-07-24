require 'base64'
class Octokey
  class Buffer
    attr_accessor :buffer, :invalid_buffer

    # to avoid DOS caused by duplicating enourmous buffers,
    # we limit the maximum size of any string stored to 100k
    MAX_STRING_SIZE = 100 * 1024

    def self.from_raw(raw = "")
      ret = new
      ret.buffer = raw.dup
      ret.buffer.force_encoding('BINARY') if ret.buffer.respond_to?(:force_encoding)
      ret
    end

    def initialize(string = "")
      self.buffer = Base64.decode64(string || "")
      buffer.force_encoding('BINARY') if buffer.respond_to?(:force_encoding)
      self.invalid_buffer = "Badly formatted Base64" unless to_s == string
    end

    def raw
      buffer
    end

    def empty?
      buffer.empty?
    end

    def to_s
      Base64.encode64(buffer).gsub("\n", "")
    end

    def <<(bytes)
      buffer << bytes
      self
    end

    def scan(n)
      raise InvalidBuffer, invalid_buffer if invalid_buffer
      ret, buf = [buffer[0...n], buffer[n..-1]]
      if ret.size < n || !buf
        raise InvalidBuffer, "Buffer too short"
      end
      self.buffer = buf
      ret
    end

    def add_uint8(x)
      raise InvalidBuffer, "Invalid uint8: #{x}" if x < 0 || x >= 2 ** 8
      buffer << [x].pack("C")
      self
    end

    def scan_uint8
      scan(1).unpack("C").first
    end

    def add_uint32(x)
      raise InvalidBuffer, "Invalid uint32: #{x}" if x < 0 || x >= 2 ** 32
      buffer << [x].pack("N")
      self
    end

    def scan_uint32
      scan(4).unpack("N").first
    end

    def add_uint64(x)
      raise InvalidBuffer, "Invalid uint64: #{x}" if x < 0 || x >= 2 ** 64
      add_uint32(x >> 32 & 0xffff_ffff)
      add_uint32(x & 0xffff_ffff)
      self
    end

    def scan_uint64
      (scan_uint32 << 32) + scan_uint32
    end

    def add_uint128(x)
      raise InvalidBuffer, "Invalid uint128: #{x}" if x < 0 || x >= 2 ** 128
      add_uint64(x >> 64 & 0xffff_ffff_ffff_ffff)
      add_uint64(x & 0xffff_ffff_ffff_ffff)
      self
    end

    def scan_uint128
      (scan_uint64 << 64) + scan_uint64
    end

    def add_time(time)
      seconds, millis = [time.to_i, (time.usec / 1000.0).round]
      add_uint64(seconds * 1000 + millis)
      self
    end

    def scan_time
      raw = scan_uint64
      seconds, millis = [raw / 1000, raw % 1000]
      Time.at(seconds) + (millis / 1000.0)
    end

    def add_ip(ipaddr)
      if ipaddr.ipv4?
        add_uint8(4)
        add_uint32(ipaddr.to_i)
      elsif ipaddr.ipv6?
        add_uint8(6)
        add_uint128(ipaddr.to_i)
      else
        raise InvalidBuffer, "Unsupported IP address: #{ipaddr.to_s}"
      end
      self
    end

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

    def add_varbytes(bytes)
      size = bytes.size
      raise InvalidBuffer, "Too much length: #{size}" if size > MAX_STRING_SIZE
      add_uint32 size
      self << bytes
    end

    def scan_varbytes
      size = scan_uint32
      raise InvalidBuffer, "Too much length: #{size}" if size > MAX_STRING_SIZE
      scan(size)
    end

    def add_string(string)
      if string.respond_to?(:encode)
        add_varbytes string.encode('UTF-8').force_encoding('BINARY')
      else
        require 'iconv'
        add_varbytes Iconv.conv('utf-8', 'utf-8', string)
      end
      self
    end

    def scan_string
      string = scan_varbytes
      if string.respond_to?(:force_encoding)
        string.force_encoding('UTF-8')
        raise InvalidBuffer, "String not UTF-8" unless string.valid_encoding?
      else
        require 'iconv'
        begin
          Iconv.conv('utf-8', 'utf-8', string)
        rescue Iconv::Failure
          raise InvalidBuffer, "String not UTF-8"
        end
      end
      string
    end

    def add_buffer(buffer)
      add_varbytes buffer.raw
      self
    end

    def scan_buffer
      Octokey::Buffer.from_raw scan_varbytes
    end

    def add_mpint(x)
      raise InvalidBuffer, "Invalid mpint: #{mpint.inspect}" if x < 0
      bytes = OpenSSL::BN.new(x.to_s, 10).to_s(2)
      bytes = "\x00" + bytes if bytes.bytes.first >= 0x80
      add_varbytes(bytes)
      self
    end

    def scan_mpint
      raw = scan_varbytes

      first, second = raw.bytes.first(2)

      # ensure only positive numbers with no superflous leading 0s
      if first >= 0x80 || first == 0x00 && second < 0x80
        raise InvalidBuffer, "Badly formatted mpint"
      end

      OpenSSL::BN.new(raw, 2)
    end

    def inspect
      "#<Octokey::Buffer @buffer=#{to_s.inspect}>"
    end

    def scan_all(*tokens)
      ret = tokens.map do |token|
        raise "invalid token type: #{token.inspect}" unless respond_to?("scan_#{token}")
        send("scan_#{token}")
      end

      scan_end
      ret
    end

    def scan_end
      raise InvalidBuffer, "Buffer too long" unless empty?
    end
  end
end
