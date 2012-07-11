describe Octokey::Buffer do
  File.read("spec/buffer.tsv").lines.each_with_index do |test, i|
    next if test.start_with?("#") || test.strip == ""

    base64, type, expected, error, comment = test.rstrip.split("\t", 5)
    buffer = Octokey::Buffer.new(base64)

    if expected == "error"
      it "should raise error on #{comment}. buffer.tsv:#{i + 1} " do

      end
    else
      it "should cope with #{comment}. buffer.tsv:#{i + 1}" do
        begin
          case type
          when "uint8"
            result, _ = buffer.scan_all(:uint8)
            result.should == expected.to_i
            Octokey::Buffer.new.tap{ |x| x.add_uint8(result) }.to_s.should == base64

          when "time"
            result, _ = buffer.scan_all(:time)
            result.should be_within(0.0005).of(Time.iso8601(expected))
            Octokey::Buffer.new.tap{ |x| x.add_time(result) }.to_s.should == base64

          when "ip"
            result, _ = buffer.scan_all(:ip)
            result.should == IPAddr.new(expected)
            Octokey::Buffer.new.tap{ |x| x.add_ip(result) }.to_s.should == base64

          when "string"
            result, _ = buffer.scan_all(:string)
            result.should == eval(%{"#{expected}"})
            Octokey::Buffer.new.tap{ |x| x.add_string(result) }.to_s.should == base64

          when "bytes"
            result, _ = buffer.scan_all(:varbytes)
            result.should == eval(%{"#{expected}"})
            Octokey::Buffer.new.tap{ |x| x.add_varbytes(result) }.to_s.should == base64

          when "mpint"
            result, _ = buffer.scan_all(:mpint)
            result.should == expected.to_i
            Octokey::Buffer.new.tap{ |x| x.add_mpint(result) }.to_s.should == base64

          end

          raise "unexpected failure" unless _ == nil
          raise "no error: #{result.inspect}" if error == "error"

        rescue Octokey::InvalidBuffer => e
          raise unless error == "error"
          e.message.should == expected
        end
      end
    end
  end
end
