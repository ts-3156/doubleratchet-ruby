require 'openssl'
require 'rbnacl'

module Util
  def generate_dh
    key = RbNaCl::PrivateKey.generate
    [key, key.public_key]
  end

  # key1: X25519形式の秘密鍵
  # key2: X25519形式の公開鍵
  def dh(key1, key2)
    RbNaCl::GroupElement.new(key2).mult(key1)
  end

  def kdf_rk(rk, dh_out)
    opt = {
        salt: rk,
        info: 'MyApplication'.unpack1('H*'),
        length: 64,
        hash: 'SHA256'
    }
    out = OpenSSL::KDF.hkdf(dh_out, **opt)
    [out[0..31], out[32..63]]
  end

  def kdf_ck(ck)
    new_ck = OpenSSL::HMAC.digest('sha256', ck, ['02'].pack('H*'))
    mk = OpenSSL::HMAC.digest('sha256', ck, ['01'].pack('H*'))
    [new_ck, mk]
  end

  # 鍵の誤用に対する耐性の問題から、SIVモードまたはCBCモードとHMACの組み合わせによるAEAD暗号方式が推奨されている。
  # どちらであっても独自実装が必要になるため、今回はライブラリで実装済みの暗号方式を採用した。
  def encrypt(mk, plaintext, ad)
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(mk)
    # メッセージキーは一度しか使用されないため、nonceは固定の値でもかまわない。
    nonce = ['00' * cipher.nonce_bytes].pack('H*')
    cipher.encrypt(nonce, plaintext, ad)
  end

  def decrypt(mk, ciphertext, ad)
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(mk)
    nonce = ['00' * cipher.nonce_bytes].pack('H*')
    cipher.decrypt(nonce, ciphertext, ad)
  end

  def message_header(dh, pn, n)
    {dh: dh, pn: pn, n: n}
  end

  def concat(ad, header)
    ad + Marshal.dump({dh: header[:dh].to_bytes, pn: header[:pn], n: header[:n]})
  end

  def ratchet_encrypt(state, plaintext, ad)
    state[:cks], mk = kdf_ck(state[:cks])
    header = message_header(state[:dhs_pub], state[:pn], state[:ns])
    state[:ns] += 1
    [header, encrypt(mk, plaintext, concat(ad, header))]
  end

  def ratchet_decrypt(state, header, ciphertext, ad)
    plaintext = try_skipped_message_keys(state, header, ciphertext, ad)
    return plaintext if plaintext

    if header[:dh] != state[:dhr]
      # 以前の受信チェーンのスキップ済みメッセージキーを保存しておく
      skip_message_keys(state, header[:pn])
      dh_ratchet(state, header)
    end

    # 新しい受信チェーンのスキップ済みメッセージキーを保存しておく
    skip_message_keys(state, header[:n])
    state[:ckr], mk = kdf_ck(state[:ckr])
    state[:nr] += 1
    decrypt(mk, ciphertext, concat(ad, header))
  end

  def try_skipped_message_keys(state, header, ciphertext, ad)
    key = [header[:dh].to_bytes, header[:n]]
    if (mk = state[:mk_skipped][key])
      state[:mk_skipped].delete(key)
      decrypt(mk, ciphertext, concat(ad, header))
    else
      nil
    end
  end

  MAX_SKIP = 100

  def skip_message_keys(state, num)
    raise 'Too many skipped message keys' if state[:nr] + MAX_SKIP < num

    if state[:ckr]
      while state[:nr] < num
        state[:ckr], mk = kdf_ck(state[:ckr])
        state[:mk_skipped][[state[:dhr].to_bytes, state[:nr]]] = mk
        state[:nr] += 1
      end
    end
  end

  def dh_ratchet(state, header)
    state[:pn] = state[:ns]
    state[:ns] = 0
    state[:nr] = 0
    state[:dhr] = header[:dh]
    state[:rk], state[:ckr] = kdf_rk(state[:rk], dh(state[:dhs], state[:dhr]))
    state[:dhs], state[:dhs_pub] = generate_dh
    state[:rk], state[:cks] = kdf_rk(state[:rk], dh(state[:dhs], state[:dhr]))
  end
end

class Person
  include Util

  attr_reader :state

  def initialize
    @state = {}
  end

  def x3dh_sender(sk, dhr, ad)
    @sk = sk
    @dhr = dhr
    @ad = ad
  end

  def x3dh_receiver(sk, dhs, dhs_pub, ad)
    @sk = sk
    @dhs = dhs
    @dhs_pub = dhs_pub
    @ad = ad
  end

  def init_ratchet_sender
    @state[:dhs], @state[:dhs_pub] = generate_dh
    @state[:dhr] = @dhr
    @state[:rk], @state[:cks] = kdf_rk(@sk, dh(@state[:dhs], @state[:dhr]))
    @state[:ckr] = nil
    @state[:ns] = 0
    @state[:nr] = 0
    @state[:pn] = 0
    @state[:mk_skipped] = {}

    @sk = @dhr = nil
  end

  def init_ratchet_receiver
    @state[:dhs] = @dhs
    @state[:dhs_pub] = @dhs_pub
    @state[:dhr] = nil
    @state[:rk] = @sk
    @state[:cks] = nil
    @state[:ckr] = nil
    @state[:ns] = 0
    @state[:nr] = 0
    @state[:pn] = 0
    @state[:mk_skipped] = {}

    @sk = @dhs = @dhs_pub = nil
  end

  def send_message(msg)
    header, ciphertext = ratchet_encrypt(@state, msg, @ad)
  end

  def receive_message(header, ciphertext)
    plaintext = ratchet_decrypt(@state, header, ciphertext, @ad)
  end
end

if __FILE__ == $0
  # X3DHで鍵交換をしていれば値を既に持っている
  AD = ['00' * 64].pack('H*')
  SK = ['00' * 32].pack('H*')
  SIGNED_PREKEY = RbNaCl::PrivateKey.generate

  alice = Person.new
  alice.x3dh_sender(SK, SIGNED_PREKEY.public_key, AD)
  alice.init_ratchet_sender

  bob = Person.new
  bob.x3dh_receiver(SK, SIGNED_PREKEY, SIGNED_PREKEY.public_key, AD)
  bob.init_ratchet_receiver

  # Step 1
  a1 = alice.send_message('A1')
  puts bob.receive_message(*a1)

  # Step 2
  b1 = bob.send_message('B1')
  puts alice.receive_message(*b1)

  # Step 3
  a2 = alice.send_message('A2')
  b2 = bob.send_message('B2')
  puts alice.receive_message(*b2)
  puts bob.receive_message(*a2)
  a3 = alice.send_message('A3')
  a4 = alice.send_message('A4')
  puts bob.receive_message(*a3)
  puts bob.receive_message(*a4)

  # Step 4
  b3 = bob.send_message('B3')
  b4 = bob.send_message('B4')
  puts alice.receive_message(*b3)
  puts alice.receive_message(*b4)
  a5 = alice.send_message('A5')
  puts bob.receive_message(*a5)
end
