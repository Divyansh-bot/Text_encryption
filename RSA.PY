from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return b64encode(ciphertext)

def rsa_decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(b64decode(ciphertext))
    return plaintext.decode()

# Example usage:
private_key, public_key = generate_key_pair()
plaintext = input("Enter the plaintext: ")

# Encrypt
encrypted_message = rsa_encrypt(public_key, plaintext)
print("Encrypted message:", encrypted_message.decode())

# Decrypt
decrypted_message = rsa_decrypt(private_key, encrypted_message)
print("Decrypted message:", decrypted_message)
