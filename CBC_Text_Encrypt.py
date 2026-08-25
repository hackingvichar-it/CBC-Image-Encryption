from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


# ---------------------------------------
# Secret Key
# 16 bytes = AES-128
# ---------------------------------------

key = b"1234567890abcdef"


# ---------------------------------------
# Take plaintext from user
# ---------------------------------------

plaintext = input("Enter text to encrypt: ")

print("\nOriginal Text:")
print(plaintext)


# ---------------------------------------
# Convert text to bytes
# ---------------------------------------

plaintext_bytes = plaintext.encode("utf-8")


# ---------------------------------------
# Add PKCS#7 padding
# ---------------------------------------

padded_text = pad(
    plaintext_bytes,
    AES.block_size
)


# ---------------------------------------
# Generate random IV
# AES block size = 16 bytes
# ---------------------------------------

iv = get_random_bytes(16)


print("\nGenerated IV:")
print(iv.hex())


# ---------------------------------------
# AES-CBC Encryption
# ---------------------------------------

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

ciphertext = cipher.encrypt(padded_text)


# ---------------------------------------
# Convert ciphertext to HEX
# ---------------------------------------

encrypted_text = ciphertext.hex()


print("\nEncrypted Text:")
print(encrypted_text)


# ---------------------------------------
# Save IV + ciphertext
# ---------------------------------------

with open("cbc_encrypted.txt", "w") as file:

    file.write(iv.hex())
    file.write("\n")
    file.write(encrypted_text)


print("\nEncrypted data saved to cbc_encrypted.txt")
