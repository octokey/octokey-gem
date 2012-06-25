require 'base64'
class Octokey
  class Buffer
    attr_accessor :buffer, :pos

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
      self.pos = 0
      buffer.force_encoding('BINARY') if @buffer.respond_to?(:force_encoding)
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
    end

    def scan(n)
      ret, buf = [buffer[0...n], buffer[n..-1]]
      if ret.size < n || !buf
        raise InvalidBuffer, "Tried to read beyond end of buffer"
      end
      self.buffer = buf
      ret
    end

    def add_uint8(x)
      raise InvalidBuffer, "Invalid uint8: #{x}" if x < 0 || x >= 2 ** 8
      buffer << [x].pack("C")
    end

    def scan_uint8
      scan(1).unpack("C").first
    end

    def add_uint32(x)
      raise InvalidBuffer, "Invalid uint32: #{x}" if x < 0 || x >= 2 ** 32
      buffer << [x].pack("N")
    end

    def scan_uint32
      scan(4).unpack("N").first
    end

    def add_uint64(x)
      raise InvalidBuffer, "Invalid uint64: #{x}" if x < 0 || x >= 2 ** 64
      add_uint32(x >> 32 & 0xffff_ffff)
      add_uint32(x & 0xffff_ffff)
    end

    def scan_uint64
      (scan_uint32 << 32) + scan_uint32
    end

    def add_uint128(x)
      raise InvalidBuffer, "Invalid uint128: #{x}" if x < 0 || x >= 2 ** 128
      add_uint64(x >> 64 & 0xffff_ffff_ffff_ffff)
      add_uint64(x & 0xffff_ffff_ffff_ffff)
    end

    def scan_uint128
      (scan_uint64 << 64) + scan_uint64
    end

    def add_time(time)
      add_uint64((time.to_f * 1000).to_i)
    end

    def scan_time
      Time.at(scan_uint64.to_f / 1000)
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
    end

    def scan_ip
      type = scan_uint8
      case type
      when 4
        IPAddr.new_ntoh scan(4)
      when 6
        IPAddr.new_ntoh scan(16)
      else
        raise InvalidBuffer, "Unsupported IP address family: #{type}"
      end
    end

    def add_varbytes(bytes)
      size = bytes.size
      raise InvalidBuffer, "String too long: #{size}" if size > MAX_STRING_SIZE
      add_uint32 size
      self << bytes
    end

    def scan_varbytes
      size = scan_uint32
      raise InvalidBuffer, "String too long: #{size}" if size > MAX_STRING_SIZE
      scan(size)
    end

    def add_string(string)
      if string.respond_to?(:encode)
        add_varbytes string.encode('BINARY')
      else
        add_varbytes string
      end
    end

    def scan_string
      string = scan_varbytes
      if string.respond_to?(:encode)
        string.encode('UTF-8')
      else
        string
      end
    rescue EncodingError => e
      raise InvalidBuffer, e
    end

    def add_buffer(buffer)
      add_varbytes buffer.raw
    end

    def scan_buffer
      Octokey::Buffer.from_raw scan_varbytes
    end

    def add_mpint(x)
      raise InvalidBuffer, "Got negative mpint" if x < 0
      bytes = OpenSSL::BN.new(x.to_s, 10).to_s(2)
      bytes = "\x00" + bytes if bytes.bytes.first >= 0x80
      add_varbytes(bytes)
    end

    def scan_mpint
      bytes = scan_varbytes

      if bytes.bytes.first >= 0x80
        raise InvalidBuffer, "Got negative mpint"
      end

      OpenSSL::BN.new(bytes, 2)
    end

    def inspect
      "#<Octokey::Buffer @buffer=#{to_s.inspect}>"
    end
  end
end
