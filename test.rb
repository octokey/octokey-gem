require 'openssl'
require 'base64'
require_relative './lib/octokey/key_fragment'
k = OpenSSL::PKey::RSA.new(2048)

a, b = Octokey::KeyFragment.split(k)

$semitrusted_server = "./octokey" << " " << Base64.strict_encode64(a.send(:half_d).to_s(2)) << " " << Base64.strict_encode64(a.send(:public_key).n.to_s(2))

m = "hello world"

half_baked = Base64.decode64(`#$semitrusted_server #{Base64.strict_encode64(m)}`)

baked = b.encrypt_some(m, half_baked)

puts k.public_decrypt baked
