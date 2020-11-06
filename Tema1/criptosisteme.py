from Crypto.Cipher import AES
from Crypto import Random

# avand in vedere ca acest lib va fi importat de catre nodul A si B, atunci este indeplinita cerinta "cheia K3 este detinuta din start de toate cele 3 noduri"
k3 = "cheiacomunicare3"


def convert_string_to_bytes(string):
	#print(type(string), string)
	string = string.encode('utf-8')
	return string


def xor_bytestrings(string1, string2):
	# consider ca am facut padarea fisierului si nu vor fi blocurile de lungime diferita de 128 bits/16 bytes
	if isinstance(string1, str):
		string1 = convert_string_to_bytes(string1)
	if isinstance(string2, str):
		string2 = convert_string_to_bytes(string2)
	xor_strings = bytes(a ^ b for (a, b) in zip(string1, string2))
	return xor_strings


def padding_string(string):
	if len(string) % AES.block_size:
		count_padding = AES.block_size - len(string) % AES.block_size
		if isinstance(string, bytes):
			string += b' ' * (count_padding - 1)
			_c = ""
			if count_padding > 9:
				_c += chr(count_padding - 10 + ord('A'))
			else:
				_c += chr(count_padding + ord('0'))
			string += _c.encode("utf-8")
		else:
			#chr_padding = chr(count_padding)
			#string = string + count_padding * chr_padding
			string = string + " " * (count_padding - 1)
			if count_padding > 9:
				string += chr(count_padding - 10 + ord('A'))
			else:
				string += chr(count_padding + ord('0'))
	return string


def unpadding_string(string_padded):
	unpadded_string = string_padded
	if len(unpadded_string):
		#chr_ascii_pad = ord(string_padded[-1])
		#if chr_ascii_pad < 16:
		#	unpadded_string = string_padded[0:-chr_ascii_pad]
		last_chr = string_padded[-1]
		if (last_chr >= ord('0') and last_chr <= ord('9')) or (last_chr>= ord('A') and last_chr<= ord('F')):
			last_index = int(chr(last_chr), 16)
			#last_index = last_chr
			if len(unpadded_string) >= last_index:
				padded = True
				for x in unpadded_string[len(unpadded_string) - last_index:-1]:
					if x != ord(" "):
						padded = False
						break
			if padded:
				unpadded_string = string_padded[0:-last_index]
			# if unpadded_string[len(unpadded_string) - last_index:] == convert_string_to_bytes("{}{}".format(" " * (last_index - 1), last_chr)):
			# 	unpadded_string = string_padded[0:-last_index]
	return unpadded_string


def get_blocks(plaintext):
	list_blocks = []
	for i in range(0, len(plaintext), AES.block_size):
		list_blocks.append(plaintext[i:i+AES.block_size])
	return list_blocks, len(list_blocks)


def encryption_ECB(plaintext, key):
	plaintext = padding_string(plaintext)
	# print('plaintext padding', plaintext)
	if isinstance(plaintext, str):
		plaintext = convert_string_to_bytes(plaintext)
	if isinstance(key, str):
		key = convert_string_to_bytes(key)
	plaintext_blocks, nr_of_blocks = get_blocks(plaintext)
	# print('plaintext_blocks', plaintext_blocks)
	encrypted_text = b''
	cipher = AES.new(key, AES.MODE_ECB)

	for block in plaintext_blocks:
		plaintext = block
		encrypted_text_current = cipher.encrypt(plaintext)
		encrypted_text += encrypted_text_current
	return encrypted_text, key, nr_of_blocks


def decryption_ECB(ciphertext, key):
	if isinstance(ciphertext, str):
		ciphertext = convert_string_to_bytes(ciphertext)
	if isinstance(key, str):
		key = convert_string_to_bytes(key)
	chiper_blocks, nr_of_blocks = get_blocks(ciphertext)
	plaintext_final = b''
	chiper = AES.new(key, AES.MODE_ECB)
	for block in chiper_blocks:
		plaintext_temp = chiper.decrypt(block)
		plaintext_final += plaintext_temp
	#print(plaintext_final)
	plaintext_unpad = unpadding_string(plaintext_final)
	# print('final decryption CBC', plaintext_unpad)
	return plaintext_unpad, nr_of_blocks


def encryption_CBC(plaintext, key, init_vector):
	# print('encryption')
	# print('init variables', plaintext, key)
	plaintext = padding_string(plaintext)
	# print('plaintext padding', plaintext)
	if isinstance(plaintext, str):
		plaintext = convert_string_to_bytes(plaintext)
	if isinstance(key, str):
		key = convert_string_to_bytes(key)
	if isinstance(init_vector, str):
		init_vector = convert_string_to_bytes(init_vector)
	plaintext_blocks, nr_of_blocks = get_blocks(plaintext)
	# print('plaintext_blocks', plaintext_blocks)
	encrypted_text = b''
	cipher = AES.new(key, AES.MODE_ECB)

	for block in plaintext_blocks:
		plaintext = block
		xor_strings = xor_bytestrings(block, init_vector)
		encrypted_text_current = cipher.encrypt(xor_strings)
		# encrypted_text_current = cipher.encrypt(block)
		init_vector = encrypted_text_current
		encrypted_text += encrypted_text_current
	# print('encrypted', encrypted_text,  'key', key, 'initvector', init_vector)
	return encrypted_text, key, nr_of_blocks


def decryption_CBC(ciphertext, key, init_vector):
	if isinstance(ciphertext, str):
		ciphertext = convert_string_to_bytes(ciphertext)
	if isinstance(key, str):
		key = convert_string_to_bytes(key)
	if isinstance(init_vector, str):
		init_vector = convert_string_to_bytes(init_vector)
	# ciphertext = ciphertext[AES.block_size:]
	chiper_blocks, nr_of_blocks = get_blocks(ciphertext)
	# print('\ndecryption')
	# print('chiper blocks', chiper_blocks)
	plaintext_final = b''
	chiper = AES.new(key, AES.MODE_ECB)
	for block in chiper_blocks:
		plaintext_temp = chiper.decrypt(block)
		plaintext_current = xor_bytestrings(plaintext_temp, init_vector)
		init_vector = block
		plaintext_final += plaintext_current
	plaintext_unpad = unpadding_string(plaintext_final)
	# print('final decryption CBC', plaintext_unpad)
	return plaintext_unpad, nr_of_blocks


def encryption_CFB(plaintext, key, init_vector):
	plaintext = padding_string(plaintext)
	if isinstance(plaintext, str):
		plaintext = convert_string_to_bytes(plaintext)
	if isinstance(key, str):
		key = convert_string_to_bytes(key)
	if isinstance(init_vector, str):
		init_vector = convert_string_to_bytes(init_vector)
	plaintext_blocks, nr_of_blocks = get_blocks(plaintext)
	encrypted_text = b''
	cipher = AES.new(key, AES.MODE_ECB)
	for block in plaintext_blocks:
		encrypted_text_temp = cipher.encrypt(init_vector)
		encrypted_text_current = xor_bytestrings(encrypted_text_temp, block)
		encrypted_text += encrypted_text_current
		init_vector = encrypted_text_current
	return encrypted_text, key, nr_of_blocks


def decryption_CFB(ciphertext, key, init_vector):
	if isinstance(ciphertext, str):
		ciphertext = convert_string_to_bytes(ciphertext)
	if isinstance(key, str):
		key = convert_string_to_bytes(key)
	if isinstance(init_vector, str):
		init_vector = convert_string_to_bytes(init_vector)
	chiper_block, nr_of_blocks = get_blocks(ciphertext)
	plaintext_final = b''
	chiper = AES.new(key, AES.MODE_ECB)
	for block in chiper_block:
		plaintext_temp = chiper.encrypt(init_vector)
		plaintext_current = xor_bytestrings(plaintext_temp, block)
		init_vector = block
		plaintext_final += plaintext_current
	plaintext_unpad = unpadding_string(plaintext_final)
	# print('final decryption CFB', plaintext_unpad)
	return plaintext_unpad, nr_of_blocks

