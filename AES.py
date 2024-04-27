from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return cipher.iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode()


key = get_random_bytes(16)  # 128-bit key (16 bytes)
plaintext = input("Enter the plaintext: ")


iv, ciphertext = aes_encrypt(key, plaintext)
print("IV:", b64encode(iv).decode())
print("Ciphertext:", b64encode(ciphertext).decode())


decrypted_plaintext = aes_decrypt(key, iv, ciphertext)
print("Decrypted plaintext:", decrypted_plaintext)
