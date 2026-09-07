#!/usr/bin/python3

def key_rounds_init(key):
    key_length = len(key)
    key_buffer = list(range(256))
    j = 0
    for i in range(256):
        j = (j + key_buffer[i] + key[i % key_length]) % 256
        key_buffer[i], key_buffer[j] = key_buffer[j], key_buffer[i]
    return key_buffer

def perform_rounds(key_buffer, data):
    i = 0
    j = 0
    output = []

    for byte in data:
        i = (i + 1) % 256
        j = (j + key_buffer[i]) % 256
        key_buffer[i], key_buffer[j] = key_buffer[j], key_buffer[i]
        k = key_buffer[(key_buffer[i] + key_buffer[j]) % 256]
        output.append(byte ^ k)

    return output

def decrypt_stream_cipher(key, ciphertext):
    key_buffer = key_rounds_init(key)
    return perform_rounds(key_buffer, ciphertext)

def decrypted_text():
    key_str = "d2c0ba035fe58753c648066d76fa793bea92ef29"
    key = [ord(c) for c in key_str]

    ciphertext = [
        0xc5, 0x7c, 0x2b, 0x05, 0x48, 0x90, 0xf3, 0xb7, 0x3f, 0x76, 0x0f, 0x5b, 0x68, 0x7b, 0x62, 0x72, 0xbd, 0xf8, 0x01, 0x9b, 0x57, 0x47, 0x1e, 0x6f, 0xdf, 0x8c, 0x55, 0x00
    ]

    decrypted_bytes = decrypt_stream_cipher(key, ciphertext)
    decrypted_text = ''.join(chr(b) for b in decrypted_bytes)

    print("Decrypted Text:", decrypted_text)
if __name__ == '__main__':
    decrypted_text()
