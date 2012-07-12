describe Octokey::Challenge do
  File.read("spec/challenge.tsv").lines.each_with_index do |line, i|
    next if line.start_with?("#") || line.strip == ""

    base64, time, expected_ip, valid, errors, comment = line.rstrip.split("\t")

    if valid == "ok"
      it "should validate #{comment} challenge.tsv:#{i + 1}" do
        c = Octokey::Challenge.from_buffer(Octokey::Buffer.new(base64))

        c.errors(:client_ip => expected_ip, :current_time => Time.iso8601(time)).should == []
      end
    else

      it "should find all errors when #{comment} challenge.tsv:#{i + 1}" do
        c = Octokey::Challenge.from_buffer(Octokey::Buffer.new(base64))

        c.errors(:client_ip => expected_ip, :current_time => Time.iso8601(time)).sort.join(", ").should == errors
      end
    end

  end
end
