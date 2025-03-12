require 'openssl'
require 'base64'
require 'json'
require 'rbnacl'

class MessageHeader
  attr_reader :dh, :pn, :n

  def initialize(dh, pn, n)
    @dh = dh.instance_of?(String) ? RbNaCl::PublicKey.new(dh) : dh
    @pn = pn
    @n = n
  end

  def dump
    JSON.dump(dh: Base64.strict_encode64(@dh.to_bytes), pn: @pn, n: @n)
  end

  def self.parse(str)
    obj = JSON.parse(str, symbolize_names: true)
    obj[:dh] = Base64.strict_decode64(obj[:dh])
    new(*obj.values_at(:dh, :pn, :n))
  end
end

module DoubleRatchet
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
        info: 'MyApplication kdf_rk'.unpack1('H*'),
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
    nonce = RbNaCl::Random.random_bytes(cipher.nonce_bytes)
    nonce + cipher.encrypt(nonce, plaintext, ad)
  end

  def decrypt(mk, ciphertext, ad)
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(mk)
    nonce = ciphertext[0..cipher.nonce_bytes - 1]
    ciphertext = ciphertext[cipher.nonce_bytes..-1]
    cipher.decrypt(nonce, ciphertext, ad)
  end

  def message_header(dh, pn, n)
    MessageHeader.new(dh, pn, n)
  end

  def concat(ad, header)
    ad + (header.instance_of?(String) ? header : header.dump)
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

    if header.dh != state[:dhr]
      # 以前の受信チェーンのスキップ済みメッセージキーを保存しておく
      skip_message_keys(state, header.pn)
      dh_ratchet(state, header)
    end

    # 新しい受信チェーンのスキップ済みメッセージキーを保存しておく
    skip_message_keys(state, header.n)
    state[:ckr], mk = kdf_ck(state[:ckr])
    state[:nr] += 1
    decrypt(mk, ciphertext, concat(ad, header))
  end

  def try_skipped_message_keys(state, header, ciphertext, ad)
    key = [header.dh.to_bytes, header.n]
    if (mk = state[:mk_skipped][key])
      state[:mk_skipped].delete(key)
      decrypt(mk, ciphertext, concat(ad, header))
    else
      nil
    end
  end

  MAX_SKIP = 100

  def skip_message_keys(state, num)
    raise 'Too many skipped messages' if state[:nr] + MAX_SKIP < num

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
    state[:dhr] = header.dh
    state[:rk], state[:ckr] = kdf_rk(state[:rk], dh(state[:dhs], state[:dhr]))
    state[:dhs], state[:dhs_pub] = generate_dh
    state[:rk], state[:cks] = kdf_rk(state[:rk], dh(state[:dhs], state[:dhr]))
  end
end

module DoubleRatchetWithHeaderEncryption
  def kdf_rk_he(rk, dh_out)
    opt = {
        salt: rk,
        info: 'MyApplication kdf_rk_he'.unpack1('H*'),
        length: 96,
        hash: 'SHA256'
    }
    out = OpenSSL::KDF.hkdf(dh_out, **opt)
    [out[0..31], out[32..63], out[64..95]]
  end

  # 同じhkが繰り返し利用されるため、nonceに重複した値を使用してはいけない
  def hencrypt(hk, plaintext)
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(hk)
    nonce = RbNaCl::Random.random_bytes(cipher.nonce_bytes)
    nonce + cipher.encrypt(nonce, plaintext, '')
  end

  def hdecrypt(hk, ciphertext)
    return nil unless hk
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(hk)
    nonce = ciphertext[0..cipher.nonce_bytes - 1]
    ciphertext = ciphertext[cipher.nonce_bytes..-1]
    cipher.decrypt(nonce, ciphertext, '')
  rescue RbNaCl::CryptoError => e
    if e.message == 'Decryption failed. Ciphertext failed verification.'
      nil
    else
      raise
    end
  end

  def ratchet_encrypt_he(state, plaintext, ad)
    state[:cks], mk = kdf_ck(state[:cks])
    header = message_header(state[:dhs_pub], state[:pn], state[:ns])
    enc_header = hencrypt(state[:hks], header.dump)
    state[:ns] += 1
    [enc_header, encrypt(mk, plaintext, concat(ad, enc_header))]
  end

  def ratchet_decrypt_he(state, enc_header, ciphertext, ad)
    plaintext = try_skipped_message_keys_he(state, enc_header, ciphertext, ad)
    return plaintext if plaintext

    header, dh_ratchet = decrypt_header(state, enc_header)

    if dh_ratchet
      skip_message_keys_he(state, header.pn)
      dh_ratchet_he(state, header)
    end

    skip_message_keys_he(state, header.n)
    state[:ckr], mk = kdf_ck(state[:ckr])
    state[:nr] += 1
    decrypt(mk, ciphertext, concat(ad, enc_header))
  end

  def try_skipped_message_keys_he(state, enc_header, ciphertext, ad)
    state[:mk_skipped].each do |(hk, n), mk|
      header = decrypt_header(hk, enc_header)
      if header && header.n == n
        state[:mk_skipped].delete([hk, n])
        return decrypt(mk, ciphertext, concat(ad, enc_header))
      end
    end

    nil
  end

  def decrypt_header(state, enc_header)
    if (plaintext = hdecrypt(state[:hkr], enc_header))
      return [MessageHeader.parse(plaintext), false]
    end
    if (plaintext = hdecrypt(state[:nhkr], enc_header))
      return [MessageHeader.parse(plaintext), true]
    end

    raise
  end

  MAX_SKIP_HE = 100

  def skip_message_keys_he(state, num)
    raise 'Too many skipped messages' if state[:nr] + MAX_SKIP_HE < num

    if state[:ckr]
      while state[:nr] < num
        state[:ckr], mk = kdf_ck(state[:ckr])
        state[:mk_skipped][[state[:hkr], state[:nr]]] = mk
        state[:nr] += 1
      end
    end
  end

  def dh_ratchet_he(state, header)
    state[:pn] = state[:ns]
    state[:ns] = 0
    state[:nr] = 0
    state[:hks] = state[:nhks]
    state[:hkr] = state[:nhkr]
    state[:dhr] = header.dh
    state[:rk], state[:ckr], state[:nhkr] = kdf_rk_he(state[:rk], dh(state[:dhs], state[:dhr]))
    state[:dhs], state[:dhs_pub] = generate_dh
    state[:rk], state[:cks], state[:nhks] = kdf_rk_he(state[:rk], dh(state[:dhs], state[:dhr]))
  end
end

class Person
  include DoubleRatchet
  include DoubleRatchetWithHeaderEncryption

  attr_reader :state

  def initialize
    @state = {}
  end

  def init_x3dh_initiator(sk, dhr, ad)
    @sk = sk
    @dhr = dhr
    @ad = ad
  end

  def init_x3dh_responder(sk, dhs, dhs_pub, ad)
    @sk = sk
    @dhs = dhs
    @dhs_pub = dhs_pub
    @ad = ad
  end

  def init_ratchet_sender(header_encryption = false)
    @header_encryption = header_encryption

    @state[:dhs], @state[:dhs_pub] = generate_dh
    @state[:dhr] = @dhr
    if header_encryption
      @state[:rk], @state[:cks], @state[:nhks] = kdf_rk_he(@sk, dh(@state[:dhs], @state[:dhr]))
      @state[:hks] = @sk
      @state[:hkr] = nil
      @state[:nhkr] = @sk
    else
      @state[:rk], @state[:cks] = kdf_rk(@sk, dh(@state[:dhs], @state[:dhr]))
    end
    @state[:ckr] = nil
    @state[:ns] = 0
    @state[:nr] = 0
    @state[:pn] = 0
    @state[:mk_skipped] = {}

    @sk = @dhr = nil
  end

  def init_ratchet_recipient(header_encryption = false)
    @header_encryption = header_encryption

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
    if header_encryption
      @state[:hks] = nil
      @state[:nhks] = @sk
      @state[:hkr] = nil
      @state[:nhkr] = @sk
    end

    @sk = @dhs = @dhs_pub = nil
  end

  def send_message(msg)
    if @header_encryption
      ratchet_encrypt_he(@state, msg, @ad)
    else
      ratchet_encrypt(@state, msg, @ad)
    end
  end

  def receive_message(header, ciphertext)
    if @header_encryption
      ratchet_decrypt_he(@state, header, ciphertext, @ad)
    else
      ratchet_decrypt(@state, header, ciphertext, @ad)
    end
  end
end

if __FILE__ == $0
  # X3DHで鍵交換をしていれば値を既に持っている
  AD = ['00' * 64].pack('H*')
  SK = ['00' * 32].pack('H*')
  SIGNED_PREKEY = RbNaCl::PrivateKey.generate

  HEADER_ENCRYPTION_FLAG = true

  alice = Person.new
  alice.init_x3dh_initiator(SK, SIGNED_PREKEY.public_key, AD)
  alice.init_ratchet_sender(HEADER_ENCRYPTION_FLAG)

  bob = Person.new
  bob.init_x3dh_responder(SK, SIGNED_PREKEY, SIGNED_PREKEY.public_key, AD)
  bob.init_ratchet_recipient(HEADER_ENCRYPTION_FLAG)

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
