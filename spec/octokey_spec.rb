describe Octokey do

  before do
    $key ||= OpenSSL::PKey::RSA.new(1024)
    $public_key ||= Octokey::PublicKey.from_key($key).to_s
    $wrong_key ||= Octokey::PublicKey.from_key(OpenSSL::PKey::RSA.new(1024)).to_s
  end

  describe "new_challenge" do
    it "should return the Base-64 encoding of a valid challenge for ipv4" do
      c = Octokey.new_challenge(:client_ip => "127.0.0.1")
      Base64.encode64(Base64.decode64(c)).gsub("\n", "").should == c
      Octokey::Challenge.from_string(c).errors(:client_ip => "127.0.0.1").should == []
    end

    it "should return the Base-64 encoding of a valid challenge for ipv6" do
      c = Octokey.new_challenge(:client_ip => "ff::ff")
      Base64.encode64(Base64.decode64(c)).gsub("\n", "").should == c
      Octokey::Challenge.from_string(c).errors(:client_ip => "ff::ff").should == []
    end
  end

  describe "sign_challenge" do
    it "should return the Base-64 encoding of a valid auth_request with valid challenge" do
      c = Octokey.new_challenge(:client_ip => "127.0.0.1")
      a = Octokey.sign_challenge(c, :request_url => "https://example.com/",
                                    :username => "frodo",
                                    :private_key => $key)
      Base64.encode64(Base64.decode64(a)).gsub("\n", "").should == a
      Octokey::AuthRequest.from_string(a).errors(:username => "frodo", :client_ip => "127.0.0.1").should == []
    end

    it "should return the Base-64 encoding of a valid auth_request with unrecognised challenge" do
      c = Octokey.new_challenge(:client_ip => "127.0.0.1")[0..48]
      a = Octokey.sign_challenge(c, :request_url => "https://example.com/",
                                    :username => "frodo",
                                    :private_key => $key)
      Base64.encode64(Base64.decode64(a)).gsub("\n", "").should == a

      ar = Octokey::AuthRequest.from_string(a) 
      ar.errors(:username => "frodo", :client_ip => "127.0.0.1").should_not == []
      ar.errors_ignoring_challenge(:username => "frodo", :client_ip => "127.0.0.1").should == []
    end
  end

  describe "can_log_in?" do
    it "should be true with a valid auth_request and key" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)

      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1",
                     :public_keys => [$public_key]).should be_can_log_in
    end

    it "should be false with a valid auth_request but wrong key" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)

      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1",
                     :public_keys => [$wrong_key]).should_not be_can_log_in
    end

    it "should by false with an invalid auth_request but valid key" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "http://example.com",
                                 :username => "frodo",
                                 :private_key => $key)

      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1",
                     :public_keys => [$public_key]).should_not be_can_log_in
    end

    it "should raise an error if invalid public keys are used" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)

      lambda{
        Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1",
                       :public_keys => ["ooops"]).can_log_in?
      }.should raise_error(ArgumentError)
    end
  end

  describe "can_sign_up?" do
    it "should be true with a valid auth_request" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)
      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").should be_can_sign_up
    end

    it "should be false with invalid auth_request" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "50.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)
      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").should_not be_can_sign_up
    end
  end

  describe "should_retry?" do
    it "should be false with a valid auth_request" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)
      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").should_not be_should_retry
    end

    it "should be false with an invalid auth request" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "baggins",
                                 :private_key => $key)
      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").should_not be_should_retry
    end

    it "should be true for an invalid challenge" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.2"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)
      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").should be_should_retry
    end
  end

  describe "username" do
    it "should return the username for a valid auth request" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)
      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").username.should == "frodo"
    end

    it "should raise an error otherwise" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://foo.example.com/",
                                 :username => "frodo",
                                 :private_key => $key)
      lambda{
        Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").username
      }.should raise_error(Octokey::InvalidRequest)
    end
  end

  describe "public_key" do
    it "should return the public_key for a valid auth request" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://example.com",
                                 :username => "frodo",
                                 :private_key => $key)
      Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").public_key.should == $public_key
    end

    it "should raise an error otherwise" do
      a = Octokey.sign_challenge(Octokey.new_challenge(:client_ip => "127.0.0.1"),
                                 :request_url => "https://foo.example.com/",
                                 :username => "frodo",
                                 :private_key => $key)
      lambda{
        Octokey.new(a, :username => "frodo", :client_ip => "127.0.0.1").public_key
      }.should raise_error(Octokey::InvalidRequest)

    end
  end
end
