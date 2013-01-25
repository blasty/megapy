#!/usr/bin/env python

import struct
from Crypto.Cipher import AES

def a32_to_str(numbers):
	return struct.pack(">" + "L"*len(numbers), *numbers).encode("hex")

def str_to_a32(data):
	data += "\x00" * (4-(len(data) % 4))
	return struct.unpack(">" + "L"*(len(data)/4), data)

def base64urlencode(data):
	return data.encode("base64").strip().replace("=","")

def base64urldecode(data):
	return (data+"==").decode("base64")

def a32_to_base64(numbers):
	return base64urlencode(a32_to_str(numbers))

def stringhash(s, aes):
	s32 = str_to_a32(s)
	h32 = [0, 0, 0, 0]

	for i in xrange(len(s32)):
		h32[i&3] ^= s32[i]

	for i in xrange(16384, 0, -1):
		h32 = struct.unpack(">LLLL", aes.encrypt(struct.pack(">LLLL", *h32)))

	return a32_to_base64([ h32[0], h32[2] ])

def prepare_key(a):
	pkey = [0x93C467E3,0x7DB0C7A4,0xD1BE3F81,0x0152CB56]

	for r in xrange(65536,0,-1):
		for j in xrange(0,len(a),4):
			key = [0, 0, 0, 0]

			for i in xrange(4):
				if i+j < len(a):
					key[i] = a[i+j]

			aes = AES.new(struct.pack(">LLLL", *key)) # lame_aes.CipherAES(key)
			pkey = struct.unpack(">LLLL", aes.encrypt(struct.pack(">LLLL", *pkey)))

	return struct.pack(">LLLL", *pkey)

def prepare_key_pw(s):
	return prepare_key(str_to_a32(s))

def loginhash(username, password):
	key = prepare_key_pw(password)
	pwd_aes = AES.new(key)
	return stringhash(username, pwd_aes)
