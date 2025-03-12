A Ruby implementation of The Double Ratchet Algorithm.

This application is written in very small Ruby code. If you want to implement The Double Ratchet Algorithm in your preferred programming language, it is better to look directly at the Ruby code.

## Usage

```ruby
bundle install
bundle exec ruby double_ratchet.rb
```

Or

```ruby
require_relative 'double_ratchet'

AD = ['00' * 64].pack('H*')
SK = ['00' * 32].pack('H*')
SIGNED_PREKEY = RbNaCl::PrivateKey.generate

HEADER_ENCRYPTION_FLAG = true

alice = Person.new
alice.x3dh_sender(SK, SIGNED_PREKEY.public_key, AD)
alice.init_ratchet_sender(HEADER_ENCRYPTION_FLAG)

bob = Person.new
bob.x3dh_recipient(SK, SIGNED_PREKEY, SIGNED_PREKEY.public_key, AD)
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
```

## Documentation

https://signal.org/docs/specifications/doubleratchet/
