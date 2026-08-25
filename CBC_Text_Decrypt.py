from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ---------------------------------------
# Same Secret Key
# ---------------------------------------

key = b"1234567890abcdef"


# ---------------------------------------
# Read IV and ciphertext
# ---------------------------------------

with open("cbc_encrypted.txt", "r") as file:

    iv_hex = file.readline().strip()
    encrypted_text = file.readline().strip()


# ---------------------------------------
# Convert HEX to bytes
# ---------------------------------------

iv = bytes.fromhex(iv_hex)

ciphertext = bytes.fromhex(encrypted_text)


print("IV:")
print(iv.hex())

print("\nEncrypted Text:")
print(encrypted_text)


# ---------------------------------------
# AES-CBC Decryption
# ---------------------------------------

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

decrypted_padded = cipher.decrypt(ciphertext)


# ---------------------------------------
# Remove PKCS#7 padding
# ---------------------------------------

plaintext_bytes = unpad(
    decrypted_padded,
    AES.block_size
)


# ---------------------------------------
# Convert bytes to text
# ---------------------------------------

plaintext = plaintext_bytes.decode("utf-8")


# ---------------------------------------
# Display plaintext
# ---------------------------------------

print("\nDecrypted Text:")
print(plaintext)
