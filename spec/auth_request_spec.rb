describe Octokey::AuthRequest do
  File.read("spec/auth_request.tsv").lines.each_with_index do |line, i|
    next if line.start_with?("#") || line.strip == ""

    base64, username, valid, retryable, errors, comment = line.rstrip.split("\t")

    args = {
      :username => username,
      :client_ip => "127.0.0.1",
      :current_time => Time.iso8601("2012-07-29T21:33:14Z")
    }

    if valid == "ok"
      it "should validate #{comment} auth_request.tsv:#{i + 1}" do
        a = Octokey::AuthRequest.from_string(base64)

        a.errors(args).should == []
      end
    else

      it "should find all errors when #{comment} auth_request.tsv:#{i + 1}" do
        a = Octokey::AuthRequest.from_string(base64)

        a.errors(args).sort.join(", ").should == errors

        if retryable == "yes"
          a.errors_ignoring_challenge(args).should == []
        else
          a.errors_ignoring_challenge(args).should_not == []
        end
      end
    end

  end
end
