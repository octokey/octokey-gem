describe Octokey::PublicKey do
  File.read("spec/public_key.tsv").lines.each_with_index do |line, i|
    next if line.start_with?("#") || line.strip == ""

    string, errors, valid, comment = line.rstrip.split("\t")

    if valid == "ok"
      it "should validate #{comment} public_key.tsv:#{i + 1}" do
        c = Octokey::PublicKey.from_string(string)

        c.errors.should == []
      end
    else

      it "should find all errors when #{comment} public_key.tsv:#{i + 1}" do
        c = Octokey::PublicKey.from_string(string)

        c.errors.sort.join(", ").should == errors
      end
    end

  end
end
